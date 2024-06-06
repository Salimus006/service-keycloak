package com.example.service.repositories;

import com.example.service.entities.Country;
import com.example.service.exceptions.ConflictException;
import org.springframework.stereotype.Component;

import java.util.*;

@Component
public class CountryRepository {

    private static final Map<Long, Country> countries = new LinkedHashMap<>(){
        {
            put(1L, new Country(1L, "USA"));
            put(2L, new Country(2L, "FRANCE"));
            put(3L, new Country(3L, "BRAZIL"));
            put(4L, new Country(4L, "ITALY"));
            put(5L, new Country(5L, "CANADA"));
        }
    };

    public List<Country> findAll(){
        return countries.values().stream().toList();
    }

    public Optional<Country> findById(Long id) {
        return Optional.ofNullable(countries.get(id));
    }

    public Country save(Country c) {
        if(countries.containsKey(c.getId())) {
            throw new ConflictException(String.format("Country already exists with the same id: %d", c.getId()));
        }
        countries.put(c.getId(), c);
        return c;
    }
}
