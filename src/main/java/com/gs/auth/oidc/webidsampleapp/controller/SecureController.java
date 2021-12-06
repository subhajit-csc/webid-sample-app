package com.gs.auth.oidc.webidsampleapp.controller;


import com.gs.auth.oidc.webidsampleapp.model.User;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.servlet.ModelAndView;

@Controller
public class SecureController {

   /* @RequestMapping(value={"/", "/login"})
    public String home(Model model) {
        //model.addAttribute("user", user);
        return "login";
    }*/
   @GetMapping(value={"/", "/login"})
   public ModelAndView login(){
       ModelAndView modelAndView = new ModelAndView();
       modelAndView.setViewName("login");
       return modelAndView;
   }
    @GetMapping(value="/home")
    public ModelAndView home(){
        ModelAndView modelAndView = new ModelAndView();
        Authentication auth = SecurityContextHolder.getContext().getAuthentication();
        //User user = userService.findUserByUserName(auth.getName());
        //modelAndView.addObject("userName", "Welcome " + user.getUserName() + "/" + user.getName() + " " + user.getLastName() + " (" + user.getEmail() + ")");

        modelAndView.addObject("userName", "Welcome " + auth.getName());
        modelAndView.addObject("adminMessage","Content Available Only for Users with Admin Role");
        modelAndView.setViewName("home");
        return modelAndView;
    }

    /*@RequestMapping("/home")
    @PreAuthorize("hasAuthority('users')")
    public String users(Model model, @AuthenticationPrincipal User user) {
        model.addAttribute("user", user);
        return "home";
    }*/

    @RequestMapping("/admins")
    @PreAuthorize("hasAuthority('admins')")
    public String admins(Model model, @AuthenticationPrincipal User user) {
        model.addAttribute("user", user);
        return "roles";
    }

    @RequestMapping("/403")
    public String unauthorized() {
        return "/403";
    }
}