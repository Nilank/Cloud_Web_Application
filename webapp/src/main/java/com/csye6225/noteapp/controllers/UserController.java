package com.csye6225.noteapp.controllers;

import com.csye6225.noteapp.models.GenericResponse;
import com.csye6225.noteapp.repository.UserRepository;
import com.csye6225.noteapp.models.User;

import com.csye6225.noteapp.services.UserService;
import com.csye6225.noteapp.shared.ResponseMessage;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.*;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.nio.charset.Charset;
import java.util.Base64;
import java.util.Date;

@RestController
public class UserController {

    private final Logger logger = LoggerFactory.getLogger(this.getClass());

    private BCryptPasswordEncoder passwordEncoder = new BCryptPasswordEncoder();

    @Autowired
    private UserRepository userRepository;

    @Autowired
    private UserService userService;

    @RequestMapping(value = "/", method = RequestMethod.GET, produces = "application/json")
    @ResponseBody
    public GenericResponse home(HttpServletRequest request, HttpServletResponse response) {

        String authorization = request.getHeader("Authorization");

        if (authorization != null && authorization.startsWith("Basic")) {

            // Authorization: Basic base64credentials
            String base64Credentials = authorization.substring("Basic".length()).trim();
            String credentials = new String(Base64.getDecoder().decode(base64Credentials), Charset.forName("UTF-8"));
            logger.info("credentials" + " = " + credentials);

            // credentials = username:password
            final String[] values = credentials.split(":", 2);
            logger.info("username/emailaddress" + " = " + values[0]);
            logger.info("password" + " = " + values[1]);
            User user = userRepository.findByemailAddress(values[0]);
            logger.info("user" + " = " + user);

            if (user != null) {
                BCryptPasswordEncoder passwordEncoder = new BCryptPasswordEncoder();
                boolean flag = passwordEncoder.matches(values[1], user.getPassword());
                logger.info("flag" + " = " + flag);
                if (flag) {
                    response.setStatus(HttpServletResponse.SC_OK);
                    return new GenericResponse(HttpStatus.OK.value(), new Date().toString());

                } else {
                    response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
                    new GenericResponse(HttpStatus.UNAUTHORIZED.value(), ResponseMessage.NOT_LOGGED_IN.getMessage());
                }
            } else {
                response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
                new GenericResponse(HttpStatus.UNAUTHORIZED.value(), ResponseMessage.NOT_LOGGED_IN.getMessage());
            }
        }

        response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);

        return new GenericResponse(HttpStatus.UNAUTHORIZED.value(), ResponseMessage.NOT_LOGGED_IN.getMessage());
    }

    @RequestMapping(value = "/user/register", method = RequestMethod.POST, produces = "application/json")
    @ResponseBody
    public GenericResponse registerUser(@RequestBody User user, HttpServletRequest request, HttpServletResponse response) {

        User existUser = userRepository.findByemailAddress(user.getEmailAddress());

        if (existUser != null) {
            response.setStatus(HttpServletResponse.SC_CONFLICT);
            return new GenericResponse(HttpStatus.CONFLICT.value(), ResponseMessage.USER_ALREADY_EXISTS.getMessage());
        }

        if (!this.userService.isEmailValid(user.getEmailAddress())) {
            response.setStatus(HttpStatus.UNPROCESSABLE_ENTITY.value());
            return new GenericResponse(HttpStatus.UNPROCESSABLE_ENTITY.value(), ResponseMessage.EMAIL_INVALID.getMessage());
        }

        if (!this.userService.isPasswordValid(user.getPassword())) {
            response.setStatus(HttpStatus.UNPROCESSABLE_ENTITY.value());
            return new GenericResponse(HttpStatus.UNPROCESSABLE_ENTITY.value(), ResponseMessage.PASSWORD_INVALID.getMessage());
        }

        String hashedPassword = passwordEncoder.encode(user.getPassword());

        user.setPassword(hashedPassword);

        logger.info("Hashed Password: " + hashedPassword);

        userRepository.save(user);

        logger.info("Create New User");

        response.setStatus(HttpServletResponse.SC_CREATED);

        return new GenericResponse(HttpStatus.CREATED.value(), ResponseMessage.USER_REGISTERATION_SUCCESS.getMessage());
    }

}
