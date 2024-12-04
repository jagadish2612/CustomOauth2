package com.example.demo.service;

import java.util.ArrayList;
import java.util.List;
import java.util.Optional;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import com.example.demo.entity.Account;
import com.example.demo.repo.AccountRepo;

@Service
public class AccountService implements UserDetailsService {

    @Autowired
    private AccountRepo accountRepo;

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    public Account save(Account acc) {
        acc.setPassword(passwordEncoder().encode(acc.getPassword()));
        return accountRepo.save(acc);
    }

    public List<Account> findAll() {
        return accountRepo.findAll();
    }

    public Optional<Account> findByEmail(String email) {
        return accountRepo.findByEmail(email);
    }

    public Optional<Account> findById(long user_id) {
        return accountRepo.findById(user_id);
    }

    public void delete(long user_id) {
        accountRepo.deleteById(user_id);
    }

    @Override
    public UserDetails loadUserByUsername(String email) throws UsernameNotFoundException {

        Optional<Account> opacc = accountRepo.findByEmail(email);
        if (!opacc.isPresent()) {
            throw new UsernameNotFoundException(email + "was not found");
        }
        Account acc = opacc.get();
        List<GrantedAuthority> authorities = new ArrayList<>();
        authorities.add(new SimpleGrantedAuthority(acc.getAuthorities()));
        return new User(acc.getEmail(), acc.getPassword(), authorities);
    }

}
