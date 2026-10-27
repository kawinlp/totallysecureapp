package org.t246osslab.easybuggy4sb.vulnerabilities;

import static org.hamcrest.CoreMatchers.not;
import static org.hamcrest.Matchers.containsString;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.model;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.junit4.SpringRunner;
import org.springframework.test.web.servlet.MockMvc;

/**
 * Tests for CodeInjectionController verifying that the code injection
 * vulnerability (CWE-94) is remediated. The fix replaces ScriptEngine.eval()
 * with Gson's JsonParser.parseString(), which is a pure data parser with no
 * code execution capability.
 */
@RunWith(SpringRunner.class)
@SpringBootTest
@AutoConfigureMockMvc
public class CodeInjectionControllerTest {

    @Autowired
    private MockMvc mockMvc;

    // -------------------------------------------------------------------
    // Positive cases: valid JSON should be accepted
    // -------------------------------------------------------------------

    @Test
    public void validJsonObjectIsAccepted() throws Exception {
        mockMvc.perform(get("/codeijc")
                .param("jsonString", "{\"key\":\"value\"}"))
                .andExpect(status().isOk())
                .andExpect(model().attributeExists("msg"))
                .andExpect(model().attributeDoesNotExist("errmsg"));
    }

    @Test
    public void validJsonArrayIsAccepted() throws Exception {
        mockMvc.perform(get("/codeijc")
                .param("jsonString", "[1,2,3]"))
                .andExpect(status().isOk())
                .andExpect(model().attributeExists("msg"))
                .andExpect(model().attributeDoesNotExist("errmsg"));
    }

    @Test
    public void validNestedJsonIsAccepted() throws Exception {
        mockMvc.perform(get("/codeijc")
                .param("jsonString", "{\"a\":{\"b\":\"c\"},\"d\":[1,2]}"))
                .andExpect(status().isOk())
                .andExpect(model().attributeExists("msg"))
                .andExpect(model().attributeDoesNotExist("errmsg"));
    }

    // -------------------------------------------------------------------
    // Negative cases: invalid JSON should be rejected gracefully
    // -------------------------------------------------------------------

    @Test
    public void invalidJsonStringIsRejected() throws Exception {
        mockMvc.perform(get("/codeijc")
                .param("jsonString", "not valid json"))
                .andExpect(status().isOk())
                .andExpect(model().attributeExists("errmsg"))
                .andExpect(model().attributeDoesNotExist("msg"));
    }

    @Test
    public void emptyJsonStringShowsPrompt() throws Exception {
        mockMvc.perform(get("/codeijc")
                .param("jsonString", ""))
                .andExpect(status().isOk())
                .andExpect(model().attributeDoesNotExist("errmsg"));
    }

    @Test
    public void missingParamShowsPrompt() throws Exception {
        mockMvc.perform(get("/codeijc"))
                .andExpect(status().isOk())
                .andExpect(model().attributeDoesNotExist("errmsg"));
    }

    // -------------------------------------------------------------------
    // Security regression tests: code injection payloads must NOT execute
    // -------------------------------------------------------------------

    /**
     * A classic code injection payload that would have executed arbitrary
     * JavaScript via ScriptEngine.eval(). With JsonParser.parseString() this
     * is treated as malformed JSON and must be rejected, not executed.
     */
    @Test
    public void codeInjectionPayloadIsRejectedNotExecuted() throws Exception {
        // Payload that would have triggered eval("JSON.parse(''); java.lang.Runtime.getRuntime().exec('id') //")
        String maliciousPayload = "'); java.lang.Runtime.getRuntime().exec('id'); //";
        mockMvc.perform(get("/codeijc")
                .param("jsonString", maliciousPayload))
                .andExpect(status().isOk())
                // Must produce an error (invalid JSON), never a success message
                .andExpect(model().attributeExists("errmsg"))
                .andExpect(model().attributeDoesNotExist("msg"));
    }

    /**
     * Single-quote escape injection: attacker closes the JSON.parse() string
     * and appends arbitrary JavaScript.
     */
    @Test
    public void singleQuoteInjectionPayloadIsRejected() throws Exception {
        String maliciousPayload = "' + java.lang.Thread.sleep(5000) + '";
        mockMvc.perform(get("/codeijc")
                .param("jsonString", maliciousPayload))
                .andExpect(status().isOk())
                .andExpect(model().attributeExists("errmsg"))
                .andExpect(model().attributeDoesNotExist("msg"));
    }

    /**
     * Payload that would use Nashorn engine's Java interop to spawn a process.
     */
    @Test
    public void nashornJavaInteropPayloadIsRejected() throws Exception {
        String maliciousPayload = "'); var runtime = java.lang.Runtime.getRuntime(); runtime.exec(['id']); //";
        mockMvc.perform(get("/codeijc")
                .param("jsonString", maliciousPayload))
                .andExpect(status().isOk())
                .andExpect(model().attributeExists("errmsg"))
                .andExpect(model().attributeDoesNotExist("msg"));
    }

    /**
     * Whitespace/newline variant — original code stripped whitespace and newlines
     * before eval; ensure stripped-down payloads are also rejected.
     */
    @Test
    public void payloadWithWhitespaceAndNewlinesIsRejected() throws Exception {
        String maliciousPayload = "' )\r\n; java.lang.System.exit(1); //";
        mockMvc.perform(get("/codeijc")
                .param("jsonString", maliciousPayload))
                .andExpect(status().isOk())
                .andExpect(model().attributeExists("errmsg"))
                .andExpect(model().attributeDoesNotExist("msg"));
    }

    /**
     * Verify that a deeply nested valid JSON object is still parsed correctly
     * (ensures the Gson parser handles complex, legitimate JSON without errors).
     */
    @Test
    public void deeplyNestedValidJsonIsAccepted() throws Exception {
        String deepJson = "{\"level1\":{\"level2\":{\"level3\":{\"value\":42}}}}";
        mockMvc.perform(get("/codeijc")
                .param("jsonString", deepJson))
                .andExpect(status().isOk())
                .andExpect(model().attributeExists("msg"))
                .andExpect(model().attributeDoesNotExist("errmsg"));
    }
}
