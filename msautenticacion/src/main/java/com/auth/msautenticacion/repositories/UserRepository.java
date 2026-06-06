package com.auth.msautenticacion.repositories;

import com.auth.msautenticacion.models.User;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.Optional;

@Repository
public interface UserRepository extends JpaRepository<User, Long> {
    // Buscar un usuario por su nombre de usuario
    Optional<User> findByUsername(String username);

    // Verificar si un email o username ya existen (útil para el registro)
    Boolean existsByUsername(String username);
    Boolean existsByEmail(String email);
}