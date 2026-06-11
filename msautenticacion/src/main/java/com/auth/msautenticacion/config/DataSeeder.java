package com.auth.msautenticacion.config;

import com.auth.msautenticacion.models.Role;
import com.auth.msautenticacion.repositories.RoleRepository;
import org.springframework.boot.CommandLineRunner;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration
public class DataSeeder {

    @Bean
    CommandLineRunner initDatabase(RoleRepository roleRepository) {
        return args -> {
            // Revisa si la tabla está vacía y crea el rol ADMIN
            if (roleRepository.findByName("ROLE_ADMIN").isEmpty()) {
                Role adminRole = new Role();
                adminRole.setName("ROLE_ADMIN");
                roleRepository.save(adminRole);
                System.out.println("Rol ROLE_ADMIN creado en la BD.");
            }

            // Revisa si la tabla está vacía y crea el rol BUYER
            if (roleRepository.findByName("ROLE_GERENTE").isEmpty()) {
                Role buyerRole = new Role();
                buyerRole.setName("ROLE_GERENTE");
                roleRepository.save(buyerRole);
                System.out.println("Rol ROLE_GERENTE creado en la BD.");
            }
            if (roleRepository.findByName("ROLE_USUARIO").isEmpty()) {
                Role buyerRole = new Role();
                buyerRole.setName("ROLE_USUARIO");
                roleRepository.save(buyerRole);
                System.out.println("Rol ROLE_USUARIO creado en la BD.");
            }
        };
    }
}