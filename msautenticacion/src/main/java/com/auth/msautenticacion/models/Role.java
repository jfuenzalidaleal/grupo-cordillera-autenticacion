package com.auth.msautenticacion.models;

import jakarta.persistence.*;
import lombok.Getter;
import lombok.Setter;
import lombok.NoArgsConstructor;

@Entity
@Table(name = "roles")
@Getter
@Setter
@NoArgsConstructor
public class Role {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    // Aquí guardaremos valores como "ROLE_ADMIN" o "ROLE_BUYER"
    @Column(unique = true, nullable = false, length = 50)
    private String name;
}