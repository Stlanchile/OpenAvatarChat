from chat_engine.chat_engine import ChatEngine
import gradio as gr
import os
import argparse
import signal
import sys

import gradio
import uvicorn
from fastapi import FastAPI
from loguru import logger

from engine_utils.directory_info import DirectoryInfo
from service.service_security.certificate_session_control import (
    install_certificate_session_control_v1,
)
from service.service_utils.logger_utils import config_loggers
from service.service_utils.service_config_loader import (
    CertificateCaptureConfigurationError,
    load_configs,
)
from service.service_utils.ssl_helpers import (
    CertificateCaptureStartupError,
    create_ssl_context,
)

project_dir = DirectoryInfo.get_project_dir()
if project_dir not in sys.path:
    sys.path.insert(0, project_dir)


def parse_args():
    parser = argparse.ArgumentParser()
    parser.add_argument("--host", type=str, help="service host address")
    parser.add_argument("--port", type=int, help="service host port")
    parser.add_argument("--config", type=str, default="config/chat_with_openai_compatible_bailian_cosyvoice.yaml", help="config file to use")
    parser.add_argument("--env", type=str, default="default", help="environment to use in config file")
    return parser.parse_args()

import torch
_original_torch_load = torch.load
def patched_torch_load(*args, **kwargs):
    if 'weights_only' not in kwargs or kwargs['weights_only'] != True:
        kwargs['weights_only'] = False
    return _original_torch_load(*args, **kwargs)
torch.load = patched_torch_load

class OpenAvatarChatWebServer(uvicorn.Server):

    def __init__(self, chat_engine: ChatEngine, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.chat_engine = chat_engine
    
    async def shutdown(self, sockets=None):
        logger.info("Start normal shutdown process")
        self.chat_engine.shutdown()
        await super().shutdown(sockets)


def setup_demo(*, mount_legacy_gradio: bool = True):
    """设置 FastAPI 应用和 Gradio 界面"""
    app = FastAPI(docs_url=None, redoc_url=None)

    css = """

    .app {
        @media screen and (max-width: 768px) {
            padding: 8px !important;
        }
    }
    footer {
        display: none !important;
    }
    """
    with gr.Blocks(css=css) as gradio_block:
        with gr.Column():
            with gr.Group() as rtc_container:
                pass

    if mount_legacy_gradio:
        gradio.mount_gradio_app(app, gradio_block, "/gradio")
    return app, gradio_block, rtc_container


def main():
    args = parse_args()
    config_from_env = os.environ.get("OPEN_AVATAR_CHAT_CONFIG", None)
    if  config_from_env:
        args.config = config_from_env
    logger_config, service_config, engine_config = load_configs(args)
    ssl_context = None
    if service_config.certificate_capture.enabled:
        ssl_context = create_ssl_context(args, service_config)

    # 设置modelscope的默认下载地址
    if not os.path.isabs(engine_config.model_root):
        os.environ['MODELSCOPE_CACHE'] = os.path.join(DirectoryInfo.get_project_dir(),
                                                      engine_config.model_root.replace('models', ''))

    config_loggers(logger_config)
    
    if service_config.certificate_capture.enabled:
        demo_app, ui, parent_block = setup_demo(mount_legacy_gradio=False)
    else:
        demo_app, ui, parent_block = setup_demo()
    if service_config.certificate_capture.enabled:
        install_certificate_session_control_v1(
            demo_app,
            service_config.certificate_capture,
        )
    
    chat_engine = ChatEngine()
    chat_engine.initialize(engine_config, app=demo_app, ui=ui, parent_block=parent_block)

    if ssl_context is None:
        ssl_context = create_ssl_context(args, service_config)

    uvicorn_options = dict(ssl_context)
    if service_config.certificate_capture.enabled:
        uvicorn_options["workers"] = service_config.workers
    uvicorn_config = uvicorn.Config(
        demo_app,
        host=service_config.host,
        port=service_config.port,
        **uvicorn_options,
    )
    server = OpenAvatarChatWebServer(chat_engine, uvicorn_config)
    server.run()


if __name__ == "__main__":
    exit_code = 0
    try:
        main()
    except KeyboardInterrupt:
        logger.info("Received KeyboardInterrupt, exiting.")
    except (
        CertificateCaptureConfigurationError,
        CertificateCaptureStartupError,
    ) as exception:
        logger.error(str(exception))
        exit_code = 1
    finally:
        signal.signal(signal.SIGINT, signal.SIG_DFL)
        signal.signal(signal.SIGTERM, signal.SIG_DFL)
        os._exit(exit_code)
