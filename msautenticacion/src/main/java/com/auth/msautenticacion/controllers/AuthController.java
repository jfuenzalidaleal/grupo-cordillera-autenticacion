package com.auth.msautenticacion.controllers;

import com.auth.msautenticacion.dto.LoginRequest;
import com.auth.msautenticacion.dto.SignupRequest;
import com.auth.msautenticacion.dto.JwtResponse;
import com.auth.msautenticacion.models.Role;
import com.auth.msautenticacion.models.User;
import com.auth.msautenticacion.repositories.RoleRepository;
import com.auth.msautenticacion.repositories.UserRepository;
import com.auth.msautenticacion.security.jwt.JwtUtils;
import com.auth.msautenticacion.security.services.UserDetailsImpl;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.*;

import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;


@RestController
@RequestMapping("/api/auth")
public class AuthController {

    @Autowired
    AuthenticationManager authenticationManager;

    @Autowired
    UserRepository userRepository;

    @Autowired
    RoleRepository roleRepository;

    @Autowired
    PasswordEncoder encoder;

    @Autowired
    JwtUtils jwtUtils;

    @PostMapping("/login")
    public ResponseEntity<?> authenticateUser(@RequestBody LoginRequest loginRequest) {

        // 1. Validar las credenciales usando el AuthenticationManager de Spring Security
        Authentication authentication = authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(loginRequest.getUsername(), loginRequest.getPassword()));

        SecurityContextHolder.getContext().setAuthentication(authentication);

        // 2. Si las credenciales son válidas, obtener los datos del usuario
        UserDetailsImpl userDetails = (UserDetailsImpl) authentication.getPrincipal();

        List<String> roles = userDetails.getAuthorities().stream()
                .map(item -> item.getAuthority())
                .collect(Collectors.toList());

        // 3. Generar el Token JWT incluyendo sus roles
        String jwt = jwtUtils.generateJwtToken(userDetails.getUsername(), roles);

        // 4. Retornar la respuesta con el token
        return ResponseEntity.ok(new JwtResponse(jwt,
                userDetails.getId(),
                userDetails.getUsername(),
                userDetails.getEmail(),
                roles));
    }

    @PostMapping("/register")
    public ResponseEntity<?> registerUser(@RequestBody SignupRequest signUpRequest) {
        // 1. Validaciones previas para evitar duplicados
        if (userRepository.existsByUsername(signUpRequest.getUsername())) {
            return ResponseEntity.badRequest().body("Error: ¡El nombre de usuario ya está en uso!");
        }

        if (userRepository.existsByEmail(signUpRequest.getEmail())) {
            return ResponseEntity.badRequest().body("Error: ¡El correo electrónico ya está en uso!");
        }

        // 2. Crear la cuenta del nuevo usuario
        User user = new User();
        user.setUsername(signUpRequest.getUsername());
        user.setEmail(signUpRequest.getEmail());
        user.setPassword(encoder.encode(signUpRequest.getPassword())); // <-- AQUÍ SE ENCRIPTA LA CONTRASEÑA CON BCRYPT

        // 3. Asignar los roles correspondientes
        Set<String> strRoles = signUpRequest.getRoles();
        Set<Role> roles = new HashSet<>();

        if (strRoles == null || strRoles.isEmpty()) {
            // Si no se especifican roles, se le asigna el rol por defecto (Comprador)
            Role buyerRole = roleRepository.findByName("ROLE_BUYER")
                    .orElseThrow(() -> new RuntimeException("Error: El Rol ROLE_BUYER no fue encontrado en la base de datos."));
            roles.add(buyerRole);
        } else {
            strRoles.forEach(role -> {
                switch (role.toLowerCase()) {
                    case "admin":
                        Role adminRole = roleRepository.findByName("ROLE_ADMIN")
                                .orElseThrow(() -> new RuntimeException("Error: El Rol ROLE_ADMIN no fue encontrado."));
                        roles.add(adminRole);
                        break;
                    default:
                        Role buyerRole = roleRepository.findByName("ROLE_BUYER")
                                .orElseThrow(() -> new RuntimeException("Error: El Rol ROLE_BUYER no fue encontrado."));
                        roles.add(buyerRole);
                }
            });
        }

        user.setRoles(roles);
        userRepository.save(user);

        return ResponseEntity.ok("¡Usuario registrado exitosamente!");
    }
}