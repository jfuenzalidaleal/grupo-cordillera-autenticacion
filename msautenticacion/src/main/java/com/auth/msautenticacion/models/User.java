package com.auth.msautenticacion.models;

import jakarta.persistence.*;
import lombok.Getter;
import lombok.Setter;
import lombok.NoArgsConstructor;

import java.util.HashSet;
import java.util.Set;

@Entity
@Table(name = "users")
@Getter
@Setter
@NoArgsConstructor
public class User {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(unique = true, nullable = false, length = 50)
    private String username;

    @Column(unique = true, nullable = false, length = 100)
    private String email;

    @Column(nullable = false)
    private String password; // Se guardará encriptada más adelante

    // Relación Muchos a Muchos con Roles
    @ManyToMany(fetch = FetchType.EAGER)
    @JoinTable(
            name = "user_roles", // Nombre de la tabla intermedia
            joinColumns = @JoinColumn(name = "user_id"), // Clave foránea de usuarios
            inverseJoinColumns = @JoinColumn(name = "role_id") // Clave foránea de roles
    )
    private Set<Role> roles = new HashSet<>();
    @Column(name = "sucursal_id", nullable = true)
    private Long sucursalId;
}