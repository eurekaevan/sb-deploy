"""Private backup archives and validated restore data."""


def archive():
    import datetime
    import hashlib
    import io
    import json
    import os
    import pathlib
    import sys
    import tarfile
    import tempfile

    from sb_deploy.context import context

    app = pathlib.Path(context.require("APP"))
    config = pathlib.Path(context.require("CONFIG"))
    action = sys.argv[1]
    allowed_roots = {"rules", "tls", "client"}

    def allowed(name):
        path = pathlib.PurePosixPath(name)
        return (
            bool(path.parts)
            and str(path) == name
            and not path.is_absolute()
            and ".." not in path.parts
            and (
                name in ("config.json", "manifest.json", "hopping.json")
                or path.parts[0] in allowed_roots
            )
        )

    def tls_objects(value):
        if isinstance(value, dict):
            if isinstance(value.get("tls"), dict):
                yield value["tls"]
            for child in value.values():
                yield from tls_objects(child)
        elif isinstance(value, list):
            for child in value:
                yield from tls_objects(child)

    if action == "create":
        directory = pathlib.Path(context.require("BACKUP_DIR"))

        def inside(path, root):
            try:
                path.resolve().relative_to(root.resolve())
                return True
            except ValueError:
                return False

        def safe_target(path):
            if (
                inside(path, app)
                or inside(path, config.parent)
                or path.resolve()
                in (
                    pathlib.Path(context.require("MANAGER")).resolve(),
                    pathlib.Path(context.require("HOP_UNIT_FILE")).resolve(),
                )
            ):
                sys.exit("备份必须保存在部署、配置和管理入口目录之外，防止备份被覆盖或随卸载删除。")

        safe_target(directory)
        if directory.is_symlink():
            sys.exit("备份目录不能是符号链接。")
        directory.mkdir(parents=True, exist_ok=True)
        directory.chmod(0o700)
        target = pathlib.Path(sys.argv[2]).absolute() if len(sys.argv) > 2 and sys.argv[2] else None
        if target is not None:
            safe_target(target)
            stream = target.open("xb")
        else:
            stream = tempfile.NamedTemporaryFile(
                mode="w+b",
                dir=directory,
                prefix="sing-box-" + datetime.datetime.now().strftime("%Y%m%d-%H%M%S") + "-",
                suffix=".tar.gz",
                delete=False,
            )
            target = pathlib.Path(stream.name)
        os.fchmod(stream.fileno(), 0o600)
        manifest = {
            "format": 1,
            "created": datetime.datetime.now(datetime.timezone.utc).isoformat(),
            "app_path": str(app),
            "kernel_version": context.get("BACKUP_KERNEL_VERSION", "unknown"),
            "service": {
                "active": context.get("BACKUP_SERVICE_ACTIVE") == "yes",
                "enabled": context.get("BACKUP_SERVICE_ENABLED") == "yes",
            },
            "files": {},
        }
        try:
            with stream, tarfile.open(fileobj=stream, mode="w:gz") as archive:
                original = config.read_bytes()
                c = json.loads(original)
                contents = {}
                referenced = set()

                def resource(obj, key, root, suffix):
                    if not obj.get(key):
                        return
                    source = pathlib.Path(obj[key]).absolute()
                    if not source.is_file():
                        sys.exit("备份引用的资源不存在或不是普通文件：" + str(source))
                    data = source.read_bytes()
                    referenced.add(str(source))
                    try:
                        relative = source.relative_to(app / root)
                        if ".." in relative.parts:
                            raise ValueError()
                        name = str(pathlib.PurePosixPath(root) / relative)
                    except ValueError:
                        digest = hashlib.sha256(
                            str(source.resolve()).encode() + b"\0" + data
                        ).hexdigest()
                        name = f"{root}/imported-{digest}{suffix}"
                    if name in contents and contents[name] != data:
                        sys.exit("备份资源路径冲突：" + name)
                    contents[name] = data
                    obj[key] = str(app / name)

                for tls in tls_objects(c):
                    for key, suffix in (("certificate_path", ".crt"), ("key_path", ".key")):
                        resource(tls, key, "tls", suffix)
                for rule in c.get("route", {}).get("rule_set", []):
                    for key in ("path", "initial_path"):
                        suffix = (
                            ".json"
                            if rule.get("format") == "source"
                            or pathlib.Path(rule.get(key, "")).suffix == ".json"
                            else ".srs"
                        )
                        resource(rule, key, "rules", suffix)
                # Managed directories remain optional; configured resources are always copied as plain bytes.
                for root in sorted(allowed_roots - {"client"}):
                    base = app / root
                    if base.is_symlink():
                        sys.exit("不能备份符号链接目录：" + str(base))
                    if not base.exists():
                        continue
                    for path in sorted(base.rglob("*")):
                        if path.is_symlink():
                            if str(path.absolute()) in referenced:
                                continue
                            sys.exit("备份只接受普通文件和目录：" + str(path))
                        if path.is_dir():
                            continue
                        if not path.is_file():
                            sys.exit("备份只接受普通文件和目录：" + str(path))
                        name = str(path.relative_to(app))
                        data = path.read_bytes()
                        if name in contents and contents[name] != data:
                            sys.exit("备份资源在读取期间已变化：" + str(path))
                        contents[name] = data
                if (app / "hopping.json").exists():
                    if (app / "hopping.json").is_symlink():
                        sys.exit("不能备份符号链接跳跃配置。")
                    contents["hopping.json"] = (app / "hopping.json").read_bytes()
                contents["config.json"] = (
                    original
                    if c == json.loads(original)
                    else (json.dumps(c, indent=2, ensure_ascii=False) + "\n").encode()
                )
                for name, data in contents.items():
                    manifest["files"][name] = hashlib.sha256(data).hexdigest()
                    info = tarfile.TarInfo(name)
                    info.size = len(data)
                    info.mode = 0o600
                    archive.addfile(info, io.BytesIO(data))
                data = json.dumps(manifest, ensure_ascii=False, indent=2).encode()
                info = tarfile.TarInfo("manifest.json")
                info.size = len(data)
                info.mode = 0o600
                archive.addfile(info, io.BytesIO(data))
        except BaseException:
            target.unlink()
            raise
        print(target)
        sys.exit()

    if action != "extract":
        sys.exit("未知备份操作。")
    source = pathlib.Path(sys.argv[2])
    destination = pathlib.Path(sys.argv[3])
    destination.mkdir(mode=0o700)
    with tarfile.open(source, "r:gz") as archive:
        members = archive.getmembers()
        names = set()
        for member in members:
            if not member.isfile() or not allowed(member.name) or member.name in names:
                sys.exit("备份包含重复、越界路径、链接或特殊文件，拒绝恢复。")
            names.add(member.name)
        if "manifest.json" not in names or "config.json" not in names:
            sys.exit("不是本脚本的备份。")
        manifest = json.load(archive.extractfile("manifest.json"))
        if (
            manifest.get("format") != 1
            or not isinstance(manifest.get("files"), dict)
            or set(manifest["files"]) != names - {"manifest.json"}
        ):
            sys.exit("备份清单不匹配。")
        for member in members:
            if member.name == "manifest.json":
                continue
            data = archive.extractfile(member).read()
            if hashlib.sha256(data).hexdigest() != manifest["files"][member.name]:
                sys.exit("备份校验失败：" + member.name)
            target = destination / member.name
            target.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
            target.write_bytes(data)
            target.chmod(0o600)
    # Relocate the archived runtime resources; derived client documents are never prerequisites.
    c = json.loads((destination / "config.json").read_text())
    old = pathlib.Path(manifest["app_path"])
    required = []

    def relocate(obj, key, root):
        if not obj.get(key):
            return
        try:
            relative = pathlib.Path(obj[key]).relative_to(old / root)
        except ValueError:
            sys.exit("备份引用了未归档的外部资源：" + obj[key])
        if ".." in relative.parts:
            sys.exit("备份资源路径越界。")
        name = str(pathlib.PurePosixPath(root) / relative)
        required.append(name)
        obj[key] = str(app / root / relative)

    for tls in tls_objects(c):
        for key in ("certificate_path", "key_path"):
            relocate(tls, key, "tls")
    for rule in c.get("route", {}).get("rule_set", []):
        for key in ("path", "initial_path"):
            relocate(rule, key, "rules")
    if old != app and c.get("experimental", {}).get("cache_file", {}).get("path") == str(
        old / "cache.db"
    ):
        c["experimental"]["cache_file"]["path"] = str(app / "cache.db")
    (destination / "config.json").write_text(json.dumps(c, indent=2, ensure_ascii=False) + "\n")
    state = manifest.get("service", {"active": False, "enabled": False})
    if not isinstance(state, dict) or any(
        type(state.get(key)) is not bool for key in ("active", "enabled")
    ):
        sys.exit("备份中的服务状态无效。")
    (destination / "manifest.json").write_text(json.dumps(manifest) + "\n")
    for name in required:
        if name not in names:
            sys.exit("备份缺少必要资源：" + name)


def service_state():
    import json
    import sys

    s = json.load(open(sys.argv[1])).get("service", {"active": False, "enabled": False})
    print("yes" if s["active"] else "no", "yes" if s["enabled"] else "no")
