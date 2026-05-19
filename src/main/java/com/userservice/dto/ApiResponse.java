package com.userservice.dto;

public class ApiResponse {

    private int    status;
    private String message;
    private Object data;

    public ApiResponse(int status, String message, Object data) {
        this.status  = status;
        this.message = message;
        this.data    = data;
    }

    // Getters
    public int    getStatus()  { return status;  }
    public String getMessage() { return message; }
    public Object getData()    { return data;    }
}