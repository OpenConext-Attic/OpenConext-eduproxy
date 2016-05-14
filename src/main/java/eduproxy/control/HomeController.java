package eduproxy.control;

import org.springframework.security.core.Authentication;
import org.springframework.ui.ModelMap;
import org.springframework.web.bind.annotation.RequestMapping;

public class HomeController {

  @RequestMapping("/")
  public String disconnect(Authentication authentication, ModelMap modelMap) {
    modelMap.addAttribute("user", authentication.getPrincipal());
    return "index";
  }
}
