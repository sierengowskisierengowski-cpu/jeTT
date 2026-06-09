import os
import unittest

from train_core_weights import (
    build_formatted_texts,
    get_training_model_name,
    get_training_system_prompt,
    normalize_training_record,
)


class TrainingPipelineTests(unittest.TestCase):
    def test_normalize_existing_output_record(self):
        record = normalize_training_record({"input": "evt", "output": "ALLOW"})

        self.assertEqual(record["input"], "evt")
        self.assertEqual(record["output"], "ALLOW")

    def test_normalize_legacy_verdict_record(self):
        record = normalize_training_record(
            {
                "input": "evt",
                "verdict": "QUARANTINE_PID_44",
                "reasoning": "Socket execution chain detected",
            }
        )

        self.assertIn("Socket execution chain detected", record["output"])
        self.assertTrue(record["output"].endswith("Final Verdict: QUARANTINE_PID_44"))

    def test_normalize_record_requires_input(self):
        with self.assertRaises(ValueError):
            normalize_training_record({"output": "ALLOW"})

    def test_normalize_record_requires_output_or_legacy_fields(self):
        with self.assertRaises(ValueError):
            normalize_training_record({"input": "evt"})

    def test_build_formatted_texts_uses_normalized_output(self):
        texts = build_formatted_texts([{"input": "evt", "output": "ALLOW"}])

        self.assertIn("<|user|>\nevt", texts[0])
        self.assertIn("<|assistant|>\nALLOW", texts[0])

    def test_training_system_prompt_allows_env_override(self):
        original = os.environ.get("JETT_TRAINING_SYSTEM_PROMPT")
        try:
            os.environ["JETT_TRAINING_SYSTEM_PROMPT"] = "custom prompt"
            self.assertEqual(get_training_system_prompt(), "custom prompt")
        finally:
            if original is None:
                os.environ.pop("JETT_TRAINING_SYSTEM_PROMPT", None)
            else:
                os.environ["JETT_TRAINING_SYSTEM_PROMPT"] = original

    def test_training_model_name_allows_env_override(self):
        original = os.environ.get("JETT_TRAINING_MODEL")
        try:
            os.environ["JETT_TRAINING_MODEL"] = "custom/model"
            self.assertEqual(get_training_model_name(), "custom/model")
        finally:
            if original is None:
                os.environ.pop("JETT_TRAINING_MODEL", None)
            else:
                os.environ["JETT_TRAINING_MODEL"] = original


if __name__ == "__main__":
    unittest.main()
