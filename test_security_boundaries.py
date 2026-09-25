"""Security regression cases: exploit effects, fixed denial, and legitimate controls."""
import copy
import unittest

import lab_agent_tool_boundary as agent
import lab_api_mass_assignment as api
import lab_ci_injection as ci
import lab_jwt_audience as jwt
import lab_mcp_consent as mcp
import lab_oauth_pkce as oauth
import lab_ssrf_redirect as ssrf
import lab_tar_traversal as archive
import lab_webhook_replay as webhook


class JWTTests(unittest.TestCase):
    def test_wrong_audience_exploit_and_fix(self):
        token = jwt.issue(jwt.claims(aud="other-service"))
        self.assertTrue(jwt.verify(token, fixed=False))
        self.assertFalse(jwt.verify(token, fixed=True))

    def test_legitimate_token(self):
        self.assertTrue(jwt.verify(jwt.issue(jwt.claims()), fixed=True))

    def test_wrong_issuer(self):
        self.assertFalse(jwt.verify(jwt.issue(jwt.claims(iss="https://other.example")), fixed=True))

    def test_expiration_boundary(self):
        self.assertFalse(jwt.verify(jwt.issue(jwt.claims(exp=jwt.NOW)), fixed=True))

    def test_missing_audience(self):
        value = jwt.claims()
        del value["aud"]
        self.assertFalse(jwt.verify(jwt.issue(value), fixed=True))

    def test_audience_array(self):
        self.assertTrue(jwt.verify(jwt.issue(jwt.claims(aud=["other", jwt.AUDIENCE])), fixed=True))

    def test_tampered_signature(self):
        token = jwt.issue(jwt.claims())
        self.assertFalse(jwt.verify(token[:-8] + "AAAAAAAA", fixed=True))

    def test_disallowed_algorithm(self):
        self.assertFalse(jwt.verify(jwt.issue(jwt.claims(), algorithm="none"), fixed=True))

    def test_malformed_token(self):
        for value in ("", "abc.def", "a.b.c", "{}.{}.{}"):
            with self.subTest(value=value):
                self.assertFalse(jwt.verify(value, fixed=True))


class OAuthTests(unittest.TestCase):
    def test_intercepted_code_exploit_and_fix(self):
        self.assertTrue(oauth.redeem(oauth.issued_code(), "wrong", fixed=False))
        self.assertFalse(oauth.redeem(oauth.issued_code(), "wrong", fixed=True))

    def test_legitimate_verifier(self):
        self.assertTrue(oauth.redeem(oauth.issued_code(), oauth.VERIFIER, fixed=True))

    def test_wrong_client(self):
        self.assertFalse(oauth.redeem(oauth.issued_code(), oauth.VERIFIER, fixed=True, client_id="attacker"))

    def test_wrong_redirect(self):
        self.assertFalse(oauth.redeem(oauth.issued_code(), oauth.VERIFIER, fixed=True,
                                     redirect_uri=oauth.REDIRECT + "/extra"))

    def test_code_replay(self):
        record = oauth.issued_code()
        self.assertTrue(oauth.redeem(record, oauth.VERIFIER, fixed=True))
        self.assertFalse(oauth.redeem(record, oauth.VERIFIER, fixed=True))

    def test_expired_code(self):
        self.assertFalse(oauth.redeem(oauth.issued_code(), oauth.VERIFIER, fixed=True, now=oauth.NOW + 60))

    def test_failed_attempt_does_not_consume_code(self):
        record = oauth.issued_code()
        self.assertFalse(oauth.redeem(record, "B" * 43, fixed=True))
        self.assertTrue(oauth.redeem(record, oauth.VERIFIER, fixed=True))

    def test_pkce_downgrade(self):
        record = oauth.issued_code()
        record["method"] = "plain"
        self.assertFalse(oauth.redeem(record, oauth.VERIFIER, fixed=True))


class MCPTests(unittest.TestCase):
    def test_cross_client_exploit_and_fix(self):
        args = ("alice", "untrusted-client", ["notes:read"], mcp.CLIENTS["untrusted-client"])
        self.assertTrue(mcp.authorize(*args, fixed=False))
        self.assertFalse(mcp.authorize(*args, fixed=True))

    def test_legitimate_grant(self):
        self.assertTrue(mcp.authorize("alice", "trusted-editor", ["notes:read"],
                                     mcp.CLIENTS["trusted-editor"], fixed=True))

    def test_scope_expansion(self):
        self.assertFalse(mcp.authorize("alice", "trusted-editor", ["notes:write"],
                                      mcp.CLIENTS["trusted-editor"], fixed=True))

    def test_grant_is_user_specific(self):
        self.assertFalse(mcp.authorize("bob", "trusted-editor", ["notes:read"],
                                      mcp.CLIENTS["trusted-editor"], fixed=True))

    def test_exact_redirect_match(self):
        self.assertFalse(mcp.authorize("alice", "trusted-editor", ["notes:read"],
                                      mcp.CLIENTS["trusted-editor"] + "/extra", fixed=True))


class SSRFTests(unittest.TestCase):
    def test_redirect_exploit_and_fix_without_backend_contact(self):
        with ssrf.fixtures() as (front, back, hits):
            self.assertEqual(ssrf.fetch_fixture("/redirect", front, back, fixed=False), ssrf.MARKER)
            self.assertEqual(hits, ["/metadata"])
            with self.assertRaises(ValueError):
                ssrf.fetch_fixture("/redirect", front, back, fixed=True)
            self.assertEqual(hits, ["/metadata"])

    def test_legitimate_fixture_request(self):
        with ssrf.fixtures() as (front, back, hits):
            self.assertEqual(ssrf.fetch_fixture("/public", front, back, fixed=True), "PUBLIC_FIXTURE_OK")
            self.assertEqual(hits, [])

    def test_transport_rejects_nonfixture_host_before_network(self):
        with self.assertRaises(ValueError):
            ssrf.fetch_fixture("/public", "https://external.example:443", "http://127.0.0.1:9999", fixed=False)

    def test_unknown_path_rejected_before_network(self):
        with self.assertRaises(ValueError):
            ssrf.fetch_fixture("http://external.example", "http://127.0.0.1:1", "http://127.0.0.1:2", fixed=False)


class CITests(unittest.TestCase):
    def test_title_injection_creates_marker_only_in_vulnerable_version(self):
        self.assertEqual(ci.run_title(ci.PAYLOAD, fixed=False)["marker"], "CI_LAB_MARKER")
        fixed = ci.run_title(ci.PAYLOAD, fixed=True)
        self.assertFalse(fixed["marker_created"])
        self.assertEqual(fixed["stdout"], ci.PAYLOAD)

    def test_legitimate_title_preserved(self):
        self.assertEqual(ci.run_title(ci.NORMAL, fixed=True)["stdout"], ci.NORMAL)

    def test_arbitrary_payload_is_not_accepted_by_demo(self):
        with self.assertRaises(ValueError):
            ci.run_title("not a shipped fixture", fixed=False)


class ArchiveTests(unittest.TestCase):
    def test_traversal_effect_and_fix(self):
        self.assertTrue(archive.extract_fixture("traversal", fixed=False)["escaped_extraction_directory"])
        fixed = archive.extract_fixture("traversal", fixed=True)
        self.assertTrue(fixed["rejected"])
        self.assertFalse(fixed["escaped_extraction_directory"])

    def test_symlink_rejected(self):
        fixed = archive.extract_fixture("symlink", fixed=True)
        self.assertTrue(fixed["rejected"])
        self.assertFalse(fixed["symlink_present"])

    def test_normal_archive_accepted(self):
        fixed = archive.extract_fixture("normal", fixed=True)
        self.assertFalse(fixed["rejected"])
        self.assertTrue(fixed["normal_file_present"])


class APITests(unittest.TestCase):
    def test_privilege_escalation_and_fix(self):
        self.assertEqual(api.update_profile(api.PROFILE, "alice", {"role": "admin"}, fixed=False)[1]["role"], "admin")
        status, profile = api.update_profile(api.PROFILE, "alice", {"role": "admin"}, fixed=True)
        self.assertEqual(status, 400)
        self.assertEqual(profile["role"], "member")

    def test_legitimate_update(self):
        status, profile = api.update_profile(api.PROFILE, "alice", {"display_name": "Alice F."}, fixed=True)
        self.assertEqual((status, profile["display_name"]), (200, "Alice F."))

    def test_rejection_is_atomic(self):
        old = copy.deepcopy(api.PROFILE)
        status, profile = api.update_profile(api.PROFILE, "alice", {"display_name": "Changed", "role": "admin"}, fixed=True)
        self.assertEqual((status, profile, api.PROFILE), (400, old, old))

    def test_other_user_denied(self):
        self.assertEqual(api.update_profile(api.PROFILE, "bob", {"display_name": "X"}, fixed=True)[0], 403)

    def test_input_schema(self):
        for patch in ({"display_name": []}, {"display_name": ""}, {"id": "bob"}):
            with self.subTest(patch=patch):
                self.assertEqual(api.update_profile(api.PROFILE, "alice", patch, fixed=True)[0], 400)


class AgentTests(unittest.TestCase):
    def test_disallowed_tool_effect_and_fix(self):
        call = {"tool": "send_report", "arguments": {"recipient": "outsider.example"}}
        self.assertTrue(agent.dispatch(call, fixed=False)["allowed"])
        self.assertFalse(agent.dispatch(call, fixed=True)["allowed"])

    def test_legitimate_read(self):
        self.assertTrue(agent.dispatch({"tool": "read_note", "arguments": {"path": "notes/summary.txt"}}, fixed=True)["allowed"])

    def test_resource_not_authorized(self):
        self.assertFalse(agent.dispatch({"tool": "read_note", "arguments": {"path": "private/demo.txt"}}, fixed=True)["allowed"])

    def test_argument_smuggling(self):
        self.assertFalse(agent.dispatch({"tool": "read_note", "arguments": {"path": "notes/summary.txt", "send_to": "outsider.example"}}, fixed=True)["allowed"])

    def test_structural_errors_fail_closed(self):
        for call in ([], {}, {"tool": "read_note", "arguments": {"path": []}}):
            with self.subTest(call=call):
                self.assertFalse(agent.dispatch(call, fixed=True)["allowed"])


class WebhookTests(unittest.TestCase):
    def test_duplicate_effect_and_fix(self):
        sig = webhook.signature("id-1", webhook.NOW, webhook.BODY)
        before, after = webhook.Consumer(fixed=False), webhook.Consumer(fixed=True)
        for _ in range(2):
            before.receive("id-1", webhook.NOW, webhook.BODY, sig)
            after.receive("id-1", webhook.NOW, webhook.BODY, sig)
        self.assertEqual((before.effects, after.effects), (2, 1))

    def test_legitimate_event(self):
        sig = webhook.signature("id-1", webhook.NOW, webhook.BODY)
        self.assertTrue(webhook.Consumer(fixed=True).receive("id-1", webhook.NOW, webhook.BODY, sig))

    def test_stale_event(self):
        timestamp = webhook.NOW - 301
        sig = webhook.signature("id-1", timestamp, webhook.BODY)
        self.assertFalse(webhook.Consumer(fixed=True).receive("id-1", timestamp, webhook.BODY, sig))

    def test_future_event(self):
        timestamp = webhook.NOW + 301
        sig = webhook.signature("id-1", timestamp, webhook.BODY)
        self.assertFalse(webhook.Consumer(fixed=True).receive("id-1", timestamp, webhook.BODY, sig))

    def test_body_tampering(self):
        sig = webhook.signature("id-1", webhook.NOW, webhook.BODY)
        self.assertFalse(webhook.Consumer(fixed=True).receive("id-1", webhook.NOW, b"tampered", sig))

    def test_id_tampering(self):
        sig = webhook.signature("id-1", webhook.NOW, webhook.BODY)
        self.assertFalse(webhook.Consumer(fixed=True).receive("id-2", webhook.NOW, webhook.BODY, sig))

    def test_bad_signature_does_not_consume_id(self):
        receiver = webhook.Consumer(fixed=True)
        self.assertFalse(receiver.receive("id-1", webhook.NOW, webhook.BODY, "v1,invalid"))
        sig = webhook.signature("id-1", webhook.NOW, webhook.BODY)
        self.assertTrue(receiver.receive("id-1", webhook.NOW, webhook.BODY, sig))


if __name__ == "__main__":
    unittest.main(verbosity=2)
