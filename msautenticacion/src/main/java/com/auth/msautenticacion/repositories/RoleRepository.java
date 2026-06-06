package com.auth.msautenticacion.repositories;

import com.auth.msautenticacion.models.Role;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.Optional;

@Repository
public interface RoleRepository extends JpaRepository<Role, Long> {
    // Este método nos permitirá buscar un rol en la BD usando su nombre
    Optional<Role> findByName(String name);
}