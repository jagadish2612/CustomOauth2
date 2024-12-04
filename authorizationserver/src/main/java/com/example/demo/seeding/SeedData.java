package com.example.demo.seeding;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.CommandLineRunner;
import org.springframework.stereotype.Component;

import com.example.demo.entity.Account;
import com.example.demo.service.AccountService;

@Component
public class SeedData implements CommandLineRunner {

    @Autowired
    private AccountService accountService;

    @Override
    public void run(String... args) throws Exception {

        Account acc1 = new Account();
        acc1.setEmail("admin@career.com");
        acc1.setPassword("admin@123");
        acc1.setAuthorities("USER_ADMIN");
        acc1.setPhonenumber("9865478951");
        acc1.setPhonenumberverified("true");
        accountService.save(acc1);

        Account acc2 = new Account();
        acc2.setEmail("student@career.com");
        acc2.setPassword("student@123");
        acc2.setAuthorities("USER_STUDENT");
        accountService.save(acc2);

        Account acc3 = new Account();
        acc3.setEmail("mentor@career.com");
        acc3.setPassword("mentor@123");
        acc3.setAuthorities("USER_MENTOR");
        accountService.save(acc3);

    }

}
