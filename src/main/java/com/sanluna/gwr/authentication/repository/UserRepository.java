package com.sanluna.gwr.authentication.repository;

import com.sanluna.commons.repository.BaseRepository;
import com.sanluna.gwr.authentication.model.User;
import org.springframework.stereotype.Repository;

@Repository
public interface UserRepository extends BaseRepository<User, Long> {

    User findByUsername(String username);


}
