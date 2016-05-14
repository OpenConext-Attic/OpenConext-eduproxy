package eduproxy.control;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.web.ErrorAttributes;
import org.springframework.core.env.Environment;
import org.springframework.stereotype.Controller;
import org.springframework.ui.ModelMap;
import org.springframework.util.Assert;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.context.request.RequestAttributes;
import org.springframework.web.context.request.ServletRequestAttributes;

import javax.servlet.http.HttpServletRequest;
import java.util.Map;

@Controller
public class ErrorController implements org.springframework.boot.autoconfigure.web.ErrorController {

  @Autowired
  private Environment environment;

  private final ErrorAttributes errorAttributes;

  @Autowired
  public ErrorController(ErrorAttributes errorAttributes) {
    Assert.notNull(errorAttributes, "ErrorAttributes must not be null");
    this.errorAttributes = errorAttributes;
  }

  @Override
  public String getErrorPath() {
    return "/error";
  }

  @RequestMapping("/error")
  public String error(HttpServletRequest request, ModelMap modelMap) {
    RequestAttributes requestAttributes = new ServletRequestAttributes(request);
    Map<String, Object> result = this.errorAttributes.getErrorAttributes(requestAttributes, false);

    modelMap.put("errorAttributes", result);

    return "error";
  }

}
