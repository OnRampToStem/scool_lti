from pathlib import Path

import uvicorn

from scale_api import events
from scale_api.settings import app_config


def main() -> None:
    """Runs app in a local development mode.

    Only use for local development testing.
    """
    run_opts: dict[str, int | bool | str] = {
        "port": 8000,
        "reload": True,
    }

    if app_config.api.use_ssl_for_app_run_local:
        cert_path = Path(__file__).parent.parent / "tests/certs"
        run_opts["port"] = 443
        run_opts["ssl_keyfile"] = f"{cert_path / 'local_ssl_key.pem'}"
        run_opts["ssl_certfile"] = f"{cert_path / 'local_ssl_cert.pem'}"

    events.on_startup_main()
    uvicorn.run(
        "scale_api.app:app",
        **run_opts,  # type: ignore[arg-type]
    )
    events.on_shutdown_main()


if __name__ == "__main__":
    main()
