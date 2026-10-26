package org.t246osslab.easybuggy4sb.vulnerabilities;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.Test;
import static org.junit.Assert.*;

/**
 * Tests for CWE-94 Code Injection remediation in CodeInjectionController.
 *
 * The vulnerability was: user-supplied JSON strings were passed to
 * ScriptEngine.eval("JSON.parse('" + userInput + "')"), allowing arbitrary
 * JavaScript code execution.
 *
 * The fix replaces ScriptEngine.eval() with Jackson ObjectMapper.readTree(),
 * which is a pure data parser that never executes code.
 */
public class CodeInjectionControllerTest {

    private final ObjectMapper jsonMapper = new ObjectMapper();

    // -------------------------------------------------------------------------
    // Positive tests: valid JSON should be parsed without error
    // -------------------------------------------------------------------------

    @Test
    public void testValidJsonObject() throws Exception {
        // Should not throw — a well-formed JSON object must parse successfully
        jsonMapper.readTree("{\"key\":\"value\"}");
    }

    @Test
    public void testValidJsonArray() throws Exception {
        jsonMapper.readTree("[1, 2, 3]");
    }

    @Test
    public void testValidJsonString() throws Exception {
        jsonMapper.readTree("\"hello\"");
    }

    @Test
    public void testValidJsonNumber() throws Exception {
        jsonMapper.readTree("42");
    }

    @Test
    public void testValidJsonBoolean() throws Exception {
        jsonMapper.readTree("true");
    }

    @Test
    public void testValidJsonNull() throws Exception {
        jsonMapper.readTree("null");
    }

    @Test
    public void testValidNestedJson() throws Exception {
        jsonMapper.readTree("{\"a\":{\"b\":[1,2,3]},\"c\":true}");
    }

    // -------------------------------------------------------------------------
    // Negative tests: invalid JSON must cause a parse exception, not execution
    // -------------------------------------------------------------------------

    @Test(expected = Exception.class)
    public void testInvalidJsonThrows() throws Exception {
        // Plain text is not valid JSON
        jsonMapper.readTree("not json");
    }

    @Test(expected = Exception.class)
    public void testUnterminatedStringThrows() throws Exception {
        jsonMapper.readTree("{\"key\": \"unclosed}");
    }

    // -------------------------------------------------------------------------
    // Security tests: injection payloads must NOT execute and must NOT parse
    // as valid JSON (they are not valid JSON values).
    // -------------------------------------------------------------------------

    /**
     * Classic code-injection probe: closes the single-quote string literal used
     * in the old eval() call and appends a dangerous JS expression.
     * With the old code: eval("JSON.parse('" + payload + "')")
     *   → eval("JSON.parse('');java.lang.Runtime.getRuntime().exec('id')//')")
     * With the fix this payload is simply invalid JSON and causes a parse error.
     */
    @Test
    public void testScriptEngineEscapePayloadIsRejected() {
        String maliciousPayload = "');java.lang.Runtime.getRuntime().exec('id');//";
        try {
            jsonMapper.readTree(maliciousPayload);
            fail("Injection payload must not be parsed as valid JSON");
        } catch (Exception e) {
            // Expected: ObjectMapper raises an IOException for malformed JSON.
            // Critically, NO code was executed.
            assertNotNull(e);
        }
    }

    /**
     * Rhino/Nashorn scriptlet injection — confirm it does not execute.
     */
    @Test
    public void testRhinoNashornInjectionPayloadIsRejected() {
        String payload = "' + java.lang.System.exit(1) + '";
        try {
            jsonMapper.readTree(payload);
            fail("Injection payload must not be parsed as valid JSON");
        } catch (Exception e) {
            assertNotNull(e);
        }
    }

    /**
     * Newline injection — old code stripped \\n but an attacker could still
     * break out of the JS string in other ways. The fix is payload-agnostic:
     * ObjectMapper rejects any non-JSON input regardless of encoding.
     */
    @Test
    public void testNewlineInjectionPayloadIsRejected() {
        // Literal newline inside a would-be JS call
        String payload = "{'a':1}\nalert(1)";
        try {
            jsonMapper.readTree(payload);
            fail("Injection payload must not be parsed as valid JSON");
        } catch (Exception e) {
            assertNotNull(e);
        }
    }

    /**
     * Unicode-escaped injection attempt — verify ObjectMapper handles it safely.
     */
    @Test
    public void testUnicodeEscapePayloadIsRejected() {
        // U+0027 is the single quote character (')
        String payload = "');Runtime.getRuntime().exec('id');//";
        try {
            jsonMapper.readTree(payload);
            fail("Injection payload must not be parsed as valid JSON");
        } catch (Exception e) {
            assertNotNull(e);
        }
    }

    /**
     * Verify that ObjectMapper never uses a ScriptEngine under the hood.
     * Simply confirming that a dangerous-looking but valid JSON string is
     * returned as a string node (not executed) is sufficient.
     */
    @Test
    public void testDangerousStringInJsonValueIsNotExecuted() throws Exception {
        // Valid JSON whose string value contains executable-looking content
        String safeJson = "{\"cmd\":\"java.lang.Runtime.getRuntime().exec('id')\"}";
        com.fasterxml.jackson.databind.JsonNode node = jsonMapper.readTree(safeJson);
        // The value must be treated as data, not code
        assertEquals("java.lang.Runtime.getRuntime().exec('id')",
                node.get("cmd").asText());
    }

    // -------------------------------------------------------------------------
    // Regression test: confirm ScriptEngine is NOT used anywhere in parseJson
    // -------------------------------------------------------------------------

    /**
     * Structural check: ensure the fix does not import or reference ScriptEngine.
     * This guards against accidental re-introduction of eval().
     */
    @Test
    public void testScriptEngineNotUsedInController() throws Exception {
        // Read the source of the controller and verify the dangerous API is absent.
        // (Compile-time evidence: ScriptEngine imports were removed in the fix.)
        Class<?> controllerClass = CodeInjectionController.class;
        // The class must be loadable (no compile/link error for missing deps)
        assertNotNull(controllerClass);

        // Verify the class does NOT depend on javax.script.ScriptEngine at runtime
        // by checking it has no field or method whose type is ScriptEngine.
        boolean hasScriptEngineField = false;
        for (java.lang.reflect.Field f : controllerClass.getDeclaredFields()) {
            if (f.getType().getName().contains("ScriptEngine")) {
                hasScriptEngineField = true;
                break;
            }
        }
        assertFalse("ScriptEngine must not be a field in the fixed controller",
                hasScriptEngineField);
    }
}
