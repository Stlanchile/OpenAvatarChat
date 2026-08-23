from torch.multiprocessing import Queue
import torch.multiprocessing as mp

import os
import sys

import librosa
from loguru import logger
import numpy as np
import requests

from engine_utils.directory_info import DirectoryInfo


# @dataclass
# class TTSConfig:
#     model: any = None
#     model_name: str = field(default=None)
#     api_url: str = field(default=None)
#     spk_id: str = field(default=None)
#     ref_audio_text: str = field(default=None)
#     ref_audio_buffer: np.ndarray = None
#     sample_rate: int = field(default=24000)
spawn_context = mp.get_context('spawn')


class TTSCosyVoiceProcessor(spawn_context.Process):
    def __init__(
        self,
        handler_root: str,
        config: any,
        input_queue: Queue,
        output_queue: Queue,
        cancelled_work_v1=None,
    ):
        super().__init__()
        self.handler_root = handler_root
        self.model = None
        self.model_name = config.model_name
        self.api_url = config.api_url
        self.spk_id = config.spk_id
        self.ref_audio_text = config.ref_audio_text
        self.ref_audio_path = config.ref_audio_path
        self.ref_audio_buffer = None
        self.sample_rate = config.sample_rate
        self.api_key = config.api_key

        self.input_queue = input_queue
        self.output_queue = output_queue
        self.cancelled_work_v1 = cancelled_work_v1
        self.dump_audio = False

    def _process_task_v1(self, task_input):
        input_text = task_input['text']
        key = task_input['key']
        session_id = task_input['session_id']
        work_ref_v1 = task_input.get("work_ref_v1")

        def is_cancelled_v1() -> bool:
            return (
                work_ref_v1 is not None
                and self.cancelled_work_v1 is not None
                and self.cancelled_work_v1.get(
                    work_ref_v1,
                    False,
                )
            )

        try:
            if is_cancelled_v1():
                return
            if len(input_text) < 1:
                logger.info('ignore empty input_text')
            elif self.model is None and self.api_url is not None:
                response = requests.get(
                    self.api_url,
                    data={
                        'tts_text': input_text,
                        'spk_id': self.spk_id,
                    },
                    stream=True,
                )
                if response.status_code != 200:
                    logger.warning("COSYVOICE_REMOTE_REQUEST_FAILED")
                else:
                    for audio_bytes in response.iter_content(
                        chunk_size=16000
                    ):
                        if is_cancelled_v1():
                            break
                        tts_speech = np.array(
                            np.frombuffer(
                                audio_bytes,
                                dtype=np.int16,
                            )
                        ).astype(np.float32) / 32767
                        output_audio = librosa.resample(
                            tts_speech,
                            orig_sr=22050,
                            target_sr=self.sample_rate,
                        )
                        self.output_queue.put({
                            'key': key,
                            'tts_speech': output_audio[np.newaxis, ...],
                            'session_id': session_id,
                        })
            else:
                response = None
                if self.model:
                    if self.ref_audio_buffer is not None:
                        response = self.model.inference_zero_shot(
                            input_text,
                            self.ref_audio_text,
                            self.ref_audio_buffer,
                            stream=True,
                        )
                    elif self.spk_id:
                        response = self.model.inference_sft(
                            input_text,
                            self.spk_id,
                            stream=True,
                        )
                    else:
                        logger.error("COSYVOICE_MODEL_CONFIG_INVALID")
                if response is not None:
                    for tts_speech in response:
                        if is_cancelled_v1():
                            break
                        tts_audio = tts_speech['tts_speech'].numpy()
                        if self.dump_audio:
                            self.audio_dump_file.write(
                                tts_audio.tobytes()
                            )
                        self.output_queue.put({
                            'key': key,
                            'tts_speech': tts_audio,
                            'session_id': session_id,
                        })
        except Exception:
            logger.error("COSYVOICE_WORKER_TASK_FAILED")
        finally:
            self.output_queue.put({
                'key': key,
                'tts_speech': None,
                'session_id': session_id,
            })

    def run(self):
        logger.remove()
        logger.add(sys.stdout, level='INFO')
        if self.dump_audio:
            dump_file_path = os.path.join(DirectoryInfo.get_project_dir(),
                                          "dump_avatar_audio.pcm")
            self.audio_dump_file = open(dump_file_path, "wb")
        logger.info('start tts processor')
        # use local model
        if self.api_key is None and self.model_name is not None:
            sys.path.append(os.path.join(self.handler_root, "CosyVoice"))
            sys.path.append(os.path.join(self.handler_root, 'CosyVoice', 'third_party', 'Matcha-TTS'))
            from handlers.tts.cosyvoice.CosyVoice.cosyvoice.utils.file_utils import load_wav
            from handlers.tts.cosyvoice.CosyVoice.cosyvoice.cli.cosyvoice import CosyVoice, CosyVoice2
            try:
                self.model = CosyVoice(model_dir=self.model_name)
            except Exception:
                try:
                    self.model = CosyVoice2(model_dir=self.model_name)
                except Exception:
                    raise TypeError('no valid model_type!')
            self.model.sample_rate = self.sample_rate
            if self.ref_audio_path:
                self.ref_audio_buffer = load_wav(self.ref_audio_path, self.sample_rate)
                self.ref_audio_text = self.ref_audio_text
            init_text = '欢迎来到中国2025'
            response = None
            if self.ref_audio_buffer is not None:
                response = self.model.inference_zero_shot(
                    init_text, self.ref_audio_text, self.ref_audio_buffer, True)
            elif self.spk_id:
                response = self.model.inference_sft(init_text, self.spk_id)
            else:
                logger.error('cosyvoice need a ref_audio or spk_id')
                return
            if response is not None:
                for tts_speech in response:
                    self.output_queue.put({
                        'key': '',
                        'tts_speech': tts_speech,
                        'session_id': ''
                    })
                    logger.debug('tts test')
        elif self.api_key is not None:
            raise TypeError('api_key not support yet')
        logger.info('tts processor started')
        while True:
            try:
                logger.debug('wait for tts task in')
                input = self.input_queue.get(timeout=5)
                logger.debug("received tts task")
            except Exception:
                continue
            self._process_task_v1(input)
