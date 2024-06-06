package com.example.service.controllers;

import com.example.service.entities.Country;
import com.example.service.repositories.CountryRepository;
import io.swagger.v3.oas.annotations.Operation;
import jakarta.validation.Valid;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@RestController
@RequestMapping("/api/countries")
public class CountryController {
    private final CountryRepository repository;

    public CountryController(CountryRepository repository) {
        this.repository = repository;
    }

    @GetMapping
    @PreAuthorize("hasAuthority('USER') or hasAuthority('ADMIN')")
    @Operation(summary = "To get list of countries. (Must have USER or ADMIN privilege)")
    public List<Country> findAll(){
        return repository.findAll();
    }

    @GetMapping("/{id}")
    @PreAuthorize("hasAuthority('USER') or hasAuthority('ADMIN')")
    @Operation(summary = "To get a country by ID. (Must have USER or ADMIN privilege)")
    public Country findById(@PathVariable Long id) {
        return repository.findById(id).orElseThrow();
    }

    @PostMapping
    @Operation(summary = "To save a new country. (Must have ADMIN privilege)")
    @PreAuthorize("hasAuthority('ADMIN')")
    public ResponseEntity<Country> save(@Valid @RequestBody Country c) {
        return ResponseEntity.ok(this.repository.save(c));
    }
}
