package org.t246osslab.easybuggy4sb.vulnerabilities;

import java.util.Locale;

import com.google.gson.JsonParser;
import com.google.gson.JsonParseException;

import org.apache.commons.lang.StringUtils;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.servlet.ModelAndView;
import org.t246osslab.easybuggy4sb.Config;
import org.t246osslab.easybuggy4sb.controller.AbstractController;

@Controller
public class CodeInjectionController extends AbstractController {

	@RequestMapping(value = Config.APP_ROOT + "/codeijc")
	public ModelAndView process(@RequestParam(value = "jsonString", required = false) String jsonString,
			ModelAndView mav, Locale locale) {
		setViewAndCommonObjects(mav, locale, "codeinjection");
        if (!StringUtils.isBlank(jsonString)) {
            parseJson(jsonString, mav, locale);
        } else {
            mav.addObject("msg", msg.getMessage("msg.enter.json.string", null, locale));
        }
		return mav;
	}

    private void parseJson(String jsonString, ModelAndView mav, Locale locale) {
        try {
            /*
             * Parse the input string as JSON using Gson's safe JsonParser.
             * This replaces the previous ScriptEngine.eval() approach which was
             * vulnerable to code injection (CWE-94) because it passed user-controlled
             * input directly to a JavaScript eval() call.
             * JsonParser.parseString() is a pure data parser with no code execution.
             */
            JsonParser.parseString(jsonString);
            mav.addObject("msg", msg.getMessage("msg.valid.json", null, locale));
        } catch (JsonParseException e) {
            mav.addObject("errmsg", msg.getMessage("msg.invalid.json",
                    new String[] { e.getMessage() }, null, locale));
        } catch (Exception e) {
            log.error("Exception occurs: ", e);
            mav.addObject("errmsg", msg.getMessage("msg.invalid.json",
                    new String[] { e.getMessage() }, null, locale));
        }
    }
}
