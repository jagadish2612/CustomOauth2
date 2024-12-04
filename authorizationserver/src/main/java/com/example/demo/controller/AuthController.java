package com.example.demo.controller;

import java.security.Principal;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class AuthController {

    @GetMapping("/data")
    public String hello(Principal principal) {
        return "Hello " + principal.getName() + ", Welcome to Daily Code Buffer!!";
    }

}
