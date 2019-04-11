package com.csye6225.noteapp.controllers;

import com.csye6225.noteapp.models.Attachment;
import com.csye6225.noteapp.models.GenericResponse;
import com.csye6225.noteapp.models.Note;
import com.csye6225.noteapp.models.Email;
import com.csye6225.noteapp.repository.AttachmentRepository;
import com.csye6225.noteapp.repository.NoteRepository;
import com.csye6225.noteapp.repository.UserRepository;
import com.csye6225.noteapp.models.User;

import com.csye6225.noteapp.services.FileHandler;
import com.csye6225.noteapp.services.UserService;
import com.csye6225.noteapp.shared.ResponseMessage;
import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.google.gson.JsonArray;
import com.google.gson.JsonObject;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.apache.commons.lang3.StringUtils;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.*;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.web.multipart.MultipartFile;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.nio.charset.Charset;
import java.util.*;

import static java.time.Clock.systemUTC;

import com.timgroup.statsd.StatsDClient;

@RestController
public class UserController {

    private final Logger logger = LoggerFactory.getLogger(this.getClass());

    private BCryptPasswordEncoder passwordEncoder = new BCryptPasswordEncoder();

    @Autowired
    private UserRepository userRepository;

    @Autowired
    private NoteRepository noteRepository;

    @Autowired
    private AttachmentRepository attachmentRepository;

    @Autowired
    private FileHandler fileHandler;

    @Autowired
    private UserService userService;

    @Autowired
    private StatsDClient statsDClient;

    @RequestMapping(value = "/", method = RequestMethod.GET, produces = "application/json")
    @ResponseBody
    public GenericResponse home(HttpServletRequest request, HttpServletResponse response) {

        statsDClient.incrementCounter("endpoint.http.get");
        logger.info("Check User logged in");

        String authorization = request.getHeader("Authorization");
        if (authorization != null && authorization.startsWith("Basic")) {
            // Authorization: Basic base64credentials
            String base64Credentials = authorization.substring("Basic".length()).trim();
            String credentials = new String(Base64.getDecoder().decode(base64Credentials), Charset.forName("UTF-8"));
            // credentials = username:password
            final String[] values = credentials.split(":", 2);
            logger.info("username/emailaddress" + " = " + values[0]);
            User user = userRepository.findByemailAddress(values[0]);
            logger.info("user" + " = " + user);
            if (user == null) {
                response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
                return new GenericResponse(HttpStatus.UNAUTHORIZED.value(), ResponseMessage.NOT_LOGGED_IN.getMessage());
            }
            BCryptPasswordEncoder passwordEncoder = new BCryptPasswordEncoder();
            boolean isPassSame = passwordEncoder.matches(values[1], user.getPassword());
            logger.info("Password query result" + " = " + isPassSame);
            if (!isPassSame) {
                response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
                return new GenericResponse(HttpStatus.UNAUTHORIZED.value(), ResponseMessage.NOT_LOGGED_IN.getMessage());
            }
            response.setStatus(HttpServletResponse.SC_OK);
            return new GenericResponse(HttpStatus.OK.value(), new Date().toString());
        }
        response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
        return new GenericResponse(HttpStatus.UNAUTHORIZED.value(), ResponseMessage.NOT_LOGGED_IN.getMessage());
    }

    @RequestMapping(value = "/user/register", method = RequestMethod.POST, produces = "application/json")
    @ResponseBody
    public GenericResponse registerUser(@RequestBody User user, HttpServletRequest request,
            HttpServletResponse response) {

        statsDClient.incrementCounter("endpoint.user.register.http.post");
        logger.info("Register User - " + user.getEmailAddress());

        User existUser = userRepository.findByemailAddress(user.getEmailAddress());
        if (existUser != null) {
            response.setStatus(HttpServletResponse.SC_CONFLICT);
            return new GenericResponse(HttpStatus.CONFLICT.value(), ResponseMessage.USER_ALREADY_EXISTS.getMessage());
        }
        if (!this.userService.isEmailValid(user.getEmailAddress())) {
            response.setStatus(HttpStatus.UNPROCESSABLE_ENTITY.value());
            return new GenericResponse(HttpStatus.UNPROCESSABLE_ENTITY.value(),
                    ResponseMessage.EMAIL_INVALID.getMessage());
        }
        if (!this.userService.isPasswordValid(user.getPassword())) {
            response.setStatus(HttpStatus.UNPROCESSABLE_ENTITY.value());
            return new GenericResponse(HttpStatus.UNPROCESSABLE_ENTITY.value(),
                    ResponseMessage.PASSWORD_INVALID.getMessage());
        }
        String hashedPassword = passwordEncoder.encode(user.getPassword());
        user.setPassword(hashedPassword);
        userRepository.save(user);
        logger.info("Created New User");
        response.setStatus(HttpServletResponse.SC_CREATED);
        return new GenericResponse(HttpStatus.CREATED.value(), ResponseMessage.USER_REGISTERATION_SUCCESS.getMessage());
    }

    // Get all notes for the user
    @GetMapping(value = "/note", produces = "application/json")
    public String getAllNotes(HttpServletRequest request, HttpServletResponse response) {

        statsDClient.incrementCounter("endpoint.note.http.get");
        logger.info("GET Note");

        JsonObject j = new JsonObject();
        JsonArray array = new JsonArray();
        User user = this.userService.authentication(request);
        if (user != null) {
            List<Note> notes = user.getNotes();
            for (Note n : notes) {
                JsonObject obj = new JsonObject();
                obj.addProperty("id", n.getId());
                obj.addProperty("content", n.getContent());
                obj.addProperty("title", n.getTitle());
                obj.addProperty("created_on", n.getCreated_on());
                obj.addProperty("last_updated_on", n.getLast_updated_on());
                this.userService.getJsonArray(n, obj);
                array.add(obj);
            }
            logger.info(array.toString());
            response.setStatus(HttpStatus.OK.value());
            return array.toString();
        }
        j.addProperty("Error", "Invalid User Credentials.");
        response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
        return j.toString();
    }

    // Create a note for the user
    @PostMapping(value = "/note", produces = "application/json")
    public String createNote(@RequestBody Note noteReq, HttpServletRequest request, HttpServletResponse response) {

        statsDClient.incrementCounter("endpoint.note.http.post");
        logger.info("Create Note");

        JsonObject j = new JsonObject();
        try {
            User user = this.userService.authentication(request);
            if (user != null) {
                Note note = new Note();
                if (!StringUtils.isBlank(noteReq.getContent()) && !StringUtils.isBlank(noteReq.getTitle())) {
                    logger.info("Saving note");
                    UUID uuid = UUID.randomUUID();
                    note.setId(uuid.toString());
                    note.setContent(noteReq.getContent());
                    note.setTitle(noteReq.getTitle());
                    String currentDate = systemUTC().instant().toString();
                    note.setCreated_on(currentDate);
                    note.setLast_updated_on(currentDate);
                    note.setUser(user);
                    noteRepository.save(note);
                    logger.info("Note saved successfully!!!");
                    j.addProperty("Success", "Note Created");
                    response.setStatus(HttpServletResponse.SC_CREATED);
                } else {
                    j.addProperty("Error", "Content/Title cannot be empty or null.");
                    response.setStatus(HttpServletResponse.SC_BAD_REQUEST);
                }
            } else {
                j.addProperty("Error", "Invalid User Credentials.");
                response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
            }
        } catch (IllegalStateException e) {
            j.addProperty("Exception", e.toString());
        } catch (Exception e) {
            j.addProperty("Exception", e.toString());
        }
        return j.toString();
    }

    // Get a note for the user
    @GetMapping(value = "/note/{id}", produces = "application/json")
    public String getNote(@PathVariable String id, HttpServletRequest request, HttpServletResponse response) {

        statsDClient.incrementCounter("endpoint.note.id.get");
        logger.info("Find Note by ID");

        JsonObject j = new JsonObject();
        try {
            User user = this.userService.authentication(request);
            if (user != null) {
                Note note = this.noteRepository.findById(id);
                if (note != null) {
                    if (user == note.getUser()) {
                        j.addProperty("id: ", note.getId());
                        j.addProperty("content: ", note.getContent());
                        j.addProperty("title: ", note.getTitle());
                        j.addProperty("created_on: ", note.getCreated_on());
                        j.addProperty("last_updated_on: ", note.getLast_updated_on());
                        this.userService.getJsonArray(note, j);
                        response.setStatus(HttpServletResponse.SC_OK);
                    } else {
                        j.addProperty("Error", "You are not the owner of this note.");
                        response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
                    }
                } else {
                    j.addProperty("Error", "Note not found.");
                    response.setStatus(HttpServletResponse.SC_NOT_FOUND);
                }
            } else {
                j.addProperty("Error", "Invalid User Credentials.");
                response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
            }
        } catch (IllegalStateException e) {
            j.addProperty("Exception", e.toString());
        } catch (Exception e) {
            j.addProperty("Exception", e.toString());
        }
        return j.toString();
    }

    // Update a note for the user
    @PutMapping(value = "/note/{id}", produces = "application/json")
    public String updateNote(@RequestBody Note note, HttpServletRequest request, @PathVariable String id,
            HttpServletResponse response) {

        statsDClient.incrementCounter("endpoint.note.id.put");
        logger.info("Find & Update the Note by ID");

        User user = this.userService.authentication(request);
        JsonObject j = new JsonObject();
        if (user != null) {
            Note n = this.noteRepository.findById(id);
            if (n != null) {
                if (!StringUtils.isBlank(note.getContent()) && !StringUtils.isBlank(note.getTitle())) {
                    if (user == n.getUser()) {
                        String currentDate = systemUTC().instant().toString();
                        n.setContent(note.getContent());
                        n.setTitle(note.getTitle());
                        n.setLast_updated_on(currentDate);
                        this.noteRepository.save(n);
                        j.addProperty("Success", "Updated Successfully!");
                        response.setStatus(HttpServletResponse.SC_NO_CONTENT);
                    } else {
                        j.addProperty("Error", "You are not the owner of this Note");
                        response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
                    }
                } else {
                    j.addProperty("Error", "Content/Title cannot be empty or null.");
                    response.setStatus(HttpServletResponse.SC_BAD_REQUEST);
                }
            } else {
                j.addProperty("Error", "Note Not Found!");
                response.setStatus(HttpServletResponse.SC_BAD_REQUEST);
            }
        } else {
            j.addProperty("Error", "Invalid User Credentials.");
            response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);

        }
        return j.toString();
    }

    // Delete a note for the user
    @DeleteMapping(value = "/note/{id}", produces = "application/json")
    public String deleteNote(@PathVariable String id, HttpServletRequest request, HttpServletResponse response) {

        statsDClient.incrementCounter("endpoint.note.id.delete");
        logger.info("DELETE Note by ID");

        JsonObject j = new JsonObject();
        User user = this.userService.authentication(request);
        if (user == null) {
            j.addProperty("Error", "Invalid User Credentials.");
            response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
            return j.toString();
        }
        Note note = this.noteRepository.findById(id);
        if (note == null) {
            j.addProperty("Error", "Note Not Found!");
            response.setStatus(HttpServletResponse.SC_BAD_REQUEST);
            return j.toString();
        }
        if (!note.getUser().getEmailAddress().equals(user.getEmailAddress())) {
            j.addProperty("Error", "You are not the owner of this Note");
            response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
            return j.toString();
        }
        List<Attachment> attachments = note.getAttachments();
        for (Attachment attachment : attachments) {
            try {
                this.fileHandler.deleteFile(attachment.getUrl(), user.getEmailAddress());
            } catch (Exception e) {
                j.addProperty("message", e.toString());
            }
        }
        int result = noteRepository.deleteNoteById(id);
        logger.info(String.valueOf(result));
        response.setStatus(HttpServletResponse.SC_NO_CONTENT);
        return j.toString();
    }

    // Get list of files attached to the note
    @GetMapping(value = "/note/{idNotes}/attachments", produces = "application/json")
    public String getFiles(@PathVariable("idNotes") String id, HttpServletRequest request,
            HttpServletResponse response) {

        statsDClient.incrementCounter("endpoint.note.id.attachments.http.get");
        logger.info("GET all the attachments attached with the note ID");

        JsonObject j = new JsonObject();
        User user = this.userService.authentication(request);
        Gson gson = new GsonBuilder().excludeFieldsWithoutExposeAnnotation().create();
        if (user != null) {
            Note note = this.noteRepository.findById(id);
            List<Attachment> attachments = new ArrayList<>();
            try {
                attachments = note.getAttachments();
            } catch (NullPointerException e) {
                logger.info("No attachments: " + e.getMessage());
            }
            String attachmentsListToJson = gson.toJson(attachments);
            logger.info("attachmentsListToJson = " + attachmentsListToJson);
            response.setStatus(HttpStatus.OK.value());
            return attachmentsListToJson;
        }
        j.addProperty("Error", "Invalid User Credentials.");
        response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
        return j.toString();
    }

    // Attach a file to the note
    @PostMapping(value = "/note/{idNotes}/attachments", produces = "application/json")
    public String attachFile(@PathVariable("idNotes") String id, @RequestParam(value = "file") MultipartFile file,
            HttpServletRequest request, HttpServletResponse response) {

        statsDClient.incrementCounter("endpoint.note.id.attachments.post");
        logger.info("Create an attachment by the note ID");

        JsonObject j = new JsonObject();
        try {
            User user = this.userService.authentication(request);
            if (file != null) {
                if (user != null) {
                    Note note = this.noteRepository.findById(id);
                    if (note != null) {
                        if (user == note.getUser()) {
                            Attachment attachment = new Attachment();
                            UUID uuid = UUID.randomUUID();
                            attachment.setId(uuid.toString());
                            String fileName = file.getOriginalFilename();
                            logger.info("filename = " + fileName);
                            String filePath = fileHandler.uploadFile(file, user.getEmailAddress());
                            logger.info("File = " + filePath);
                            attachment.setUrl(filePath);
                            attachment.setNote(note);
                            attachmentRepository.save(attachment);
                            j.addProperty("Success", "File attached");
                            response.setStatus(HttpServletResponse.SC_CREATED);
                        } else {
                            j.addProperty("Error", "Invalid User Credentials.");
                            response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
                        }
                    } else {
                        j.addProperty("Error", "Note not found");
                        response.setStatus(HttpServletResponse.SC_BAD_REQUEST);
                    }
                } else {
                    j.addProperty("Error", "Invalid User Credentials.");
                    response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
                }
            } else {
                j.addProperty("Error", "Please select a file");
                response.setStatus(HttpServletResponse.SC_BAD_REQUEST);
            }
        } catch (IllegalStateException e) {
            j.addProperty("message", e.toString());
        } catch (Exception e) {
            j.addProperty("message", e.toString());
        }
        return j.toString();
    }

    // Update file attached to the note
    @PutMapping(value = "/note/{idNotes}/attachments/{idAttachments}", produces = "application/json")
    public String updateFile(@RequestParam(value = "file") MultipartFile file, @PathVariable("idNotes") String idNote,
            @PathVariable("idAttachments") String idAttachment, HttpServletRequest request,
            HttpServletResponse response) {

        statsDClient.incrementCounter("endpoint.note.id.attachments.id.put");
        logger.info("Update the attachment by the attachment ID");

        JsonObject j = new JsonObject();
        try {
            User user = this.userService.authentication(request);
            if (user != null) {
                Attachment attachment = this.attachmentRepository.findById(idAttachment);
                if (attachment != null) {
                    Note note = this.noteRepository.findById(idNote);
                    if ((note != null) && (note == attachment.getNote())) {
                        if (file != null) {
                            if (user == attachment.getNote().getUser()) {
                                String fileName = file.getOriginalFilename();
                                logger.info("filename = " + fileName);
                                String filePath = fileHandler.uploadFile(file, user.getEmailAddress());
                                String deleteResult = this.fileHandler.deleteFile(attachment.getUrl(),
                                        user.getEmailAddress());
                                logger.info("File = " + filePath);
                                attachment.setUrl(filePath);
                                attachment.setNote(note);
                                this.attachmentRepository.save(attachment);
                                j.addProperty("Success", "Updated Successfully!");
                                response.setStatus(HttpServletResponse.SC_NO_CONTENT);
                            } else {
                                j.addProperty("Error", "You are not the owner of the attachment.");
                                response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
                            }
                        } else {
                            j.addProperty("Error", "Sorry, attachment cannot be null/empty.");
                            response.setStatus(HttpServletResponse.SC_BAD_REQUEST);
                        }
                    } else {
                        j.addProperty("Error", "Note not found");
                        response.setStatus(HttpServletResponse.SC_BAD_REQUEST);
                    }
                } else {
                    j.addProperty("Error", "Attachment not found.");
                    response.setStatus(HttpServletResponse.SC_BAD_REQUEST);
                }
            } else {
                j.addProperty("Error", "Invalid User Credentials.");
                response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
            }

        } catch (Exception e) {
            j.addProperty("message", e.toString());
        }
        return j.toString();
    }

    // Delete file attached to the transaction
    @DeleteMapping(value = "/note/{idNotes}/attachments/{idAttachments}", produces = "*/*")
    public String deleteFile(@PathVariable("idNotes") String idNote, @PathVariable("idAttachments") String idAttachment,
            HttpServletRequest request, HttpServletResponse response) {

        statsDClient.incrementCounter("endpoint.note.id.attachments.id.http.delete");
        logger.info("Delete the attachment by the attachment ID");

        JsonObject j = new JsonObject();
        try {
            User user = this.userService.authentication(request);
            if (user != null) {
                Attachment attachment = this.attachmentRepository.findById(idAttachment);
                if (attachment != null) {
                    Note note = this.noteRepository.findById(idNote);
                    if ((note != null) && (note == attachment.getNote())) {
                        if (user == attachment.getNote().getUser()) {
                            String deleteResult = this.fileHandler.deleteFile(attachment.getUrl(),
                                    user.getEmailAddress());
                            // if (deleteResult != null) {
                            this.attachmentRepository.deleteAttachmentById(idAttachment);
                            response.setStatus(HttpServletResponse.SC_NO_CONTENT);
                            // } else {
                            // j.addProperty("Error", "File does not exist!!");
                            // response.setStatus(HttpServletResponse.SC_INTERNAL_SERVER_ERROR);
                            // }
                        } else {
                            j.addProperty("Error", "Invalid User Credentials.");
                            response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
                        }
                    } else {
                        j.addProperty("Error", "Note not found or attachment doesn't belong to the note");
                        response.setStatus(HttpServletResponse.SC_BAD_REQUEST);
                    }
                } else {
                    j.addProperty("Error", "Attachment not found");
                    response.setStatus(HttpServletResponse.SC_BAD_REQUEST);
                }
            } else {
                j.addProperty("Error", "Invalid User Credentials.");
                response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
            }
        } catch (IllegalStateException e) {
            j.addProperty("message", e.toString());
        } catch (Exception e) {
            j.addProperty("message", e.toString());
        }
        return j.toString();
    }

    @PostMapping(value = "/pwdreset", produces = "application/json")
    public String generateResetToken(@RequestBody Email email, HttpServletRequest request,
            HttpServletResponse response) {

        statsDClient.incrementCounter("endpoint.reset.http.post");
        logger.info("generateResetToken - Start ");
        logger.info("email" + " " + email.getEmail());
        JsonObject j = new JsonObject();

        try {
            User user = userRepository.findByemailAddress(email.getEmail());
            if (user != null) {
                userService.sendMessage(email.getEmail());
                j.addProperty("message", "Password reset email sent");
                response.setStatus(HttpServletResponse.SC_CREATED);

            } else {
                logger.info("user not present");
                j.addProperty("Error", "Email does not exist!");
                response.setStatus(HttpServletResponse.SC_BAD_REQUEST);
            }

        } catch (Exception e) {
            logger.error("Exception in generating reset token : " + e.getMessage());
            j.addProperty("message", "Reset email failed");
            response.setStatus(HttpServletResponse.SC_BAD_REQUEST);
        }

        logger.info("generateResetToken - End ");

        return j.toString();

    }

}
