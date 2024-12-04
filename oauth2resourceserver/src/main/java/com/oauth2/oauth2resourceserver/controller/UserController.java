package com.oauth2.oauth2resourceserver.controller;

import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class UserController {

    @GetMapping("/api/users")
    @PreAuthorize("hasAuthority('SCOPE_api.read')")
    public String[] getUser() {
        return new String[] { "Shabbir", "Nikhil", "Shivam" };
    }

    @GetMapping("/api/data")
    @PreAuthorize("hasAuthority('SCOPE_api.read')")
    public String getdata() {
        return "hi this is resource server";
    }
}
