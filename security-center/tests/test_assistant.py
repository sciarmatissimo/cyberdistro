"""Unit tests for the local AI assistant (offline KB + model plumbing)."""

import unittest

from cyberdistro_sc.tools import assistant as ai
from cyberdistro_sc import i18n


class TestOfflineKB(unittest.TestCase):
    def setUp(self):
        i18n.set_default_lang("it")

    def tearDown(self):
        i18n.set_default_lang("it")

    def test_https_question_it(self):
        a = ai.offline_answer("perché non riesco a leggere i contenuti https?")
        self.assertIn("cifrat", a.lower())
        self.assertIn("modalità base", a.lower())

    def test_bridge_question_en(self):
        i18n.set_default_lang("en")
        a = ai.offline_answer("what is the transparent bridge?")
        self.assertIn("bridge", a.lower())
        self.assertIn("basic mode", a.lower())

    def test_unknown_question_offers_help(self):
        a = ai.offline_answer("qualcosa di totalmente diverso")
        self.assertTrue(len(a) > 20)

    def test_context_included(self):
        a = ai.offline_answer("chi c'è sulla rete?", context="192.168.1.5 → example.com")
        self.assertIn("example.com", a)


class TestModelPlumbing(unittest.TestCase):
    def test_build_payload_openai_and_ollama(self):
        p = ai.build_payload("openai", "ciao", context="ctx", model="m")
        self.assertEqual(p["model"], "m")
        self.assertEqual(p["messages"][-1]["content"], "ciao")
        self.assertTrue(any("ctx" in m["content"] for m in p["messages"]))
        self.assertEqual(p.get("stream"), False)
        po = ai.build_payload("ollama", "ciao")
        self.assertEqual(po["stream"], False)
        self.assertIn("options", po)

    def test_parse_response(self):
        self.assertEqual(
            ai.parse_response("openai", {"choices": [{"message": {"content": "hi "}}]}), "hi")
        self.assertEqual(
            ai.parse_response("ollama", {"message": {"content": " yo "}}), "yo")
        self.assertEqual(ai.parse_response("openai", {"bad": 1}), "")

    def test_parse_response_strips_think_blocks(self):
        r = {"choices": [{"message": {"content": "<think>ragiono...</think>\nRisposta pulita."}}]}
        self.assertEqual(ai.parse_response("openai", r), "Risposta pulita.")

    def test_openai_payload_disables_thinking(self):
        p = ai.build_payload("openai", "ciao")
        self.assertEqual(p["chat_template_kwargs"]["enable_thinking"], False)

    def test_available_uses_prober(self):
        ok, kind, url = ai.available(prober=lambda u, timeout=1.5: "11434" in u)
        self.assertTrue(ok)
        self.assertEqual(kind, "ollama")

    def test_answer_uses_model_when_reachable(self):
        captured = {}

        def transport(url, payload, timeout=60.0):
            captured["url"] = url
            return {"choices": [{"message": {"content": "risposta del modello"}}]}
        text, used = ai.answer("domanda", prober=lambda u, timeout=1.5: u.endswith("8080/v1/chat/completions"),
                               transport=transport)
        self.assertTrue(used)
        self.assertEqual(text, "risposta del modello")

    def test_answer_falls_back_offline_on_error(self):
        def boom(url, payload, timeout=60.0):
            raise OSError("no server")
        text, used = ai.answer("cos'è il bridge?", prober=lambda u, timeout=1.5: True,
                               transport=boom)
        self.assertFalse(used)
        self.assertIn("ponte", text.lower())

    def test_answer_offline_when_no_model(self):
        text, used = ai.answer("cos'è il bridge?", prober=lambda u, timeout=1.5: False,
                               starter=lambda: None)
        self.assertFalse(used)
        self.assertTrue(text)

    def test_answer_starts_local_model_on_demand(self):
        captured = {}

        def transport(url, payload, timeout=60.0):
            captured["url"] = url
            return {"choices": [{"message": {"content": "risposta locale"}}]}
        text, used = ai.answer(
            "domanda libera",
            prober=lambda u, timeout=1.5: False,                 # nothing already listening
            starter=lambda: "http://127.0.0.1:5555/v1/chat/completions",
            transport=transport)
        self.assertTrue(used)
        self.assertEqual(text, "risposta locale")
        self.assertIn("5555", captured["url"])

    def test_status_reports_model_when_reachable(self):
        kind, detail = ai.status(prober=lambda u, timeout=1.5: "8080" in u)
        self.assertEqual(kind, "model")

    def test_status_offline_without_model(self):
        kind, detail = ai.status(prober=lambda u, timeout=1.5: False)
        self.assertIn(kind, ("ready", "offline"))


if __name__ == "__main__":
    unittest.main()
