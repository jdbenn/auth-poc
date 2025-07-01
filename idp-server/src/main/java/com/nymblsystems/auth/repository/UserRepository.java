package com.nymblsystems.auth.repository;

import com.nymblsystems.auth.model.ClientUser;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

@Repository
public interface UserRepository extends JpaRepository<ClientUser,Long> {
    ClientUser findByUsername(String username);
    ClientUser findByEmail(String email);
    Boolean existsByUsername(String username);
}
