package com.github.highcumontoa.springaccessguardjava.web.dto;

import java.time.Instant;

/** Uniform, explainable error body. */
public record ErrorResponse(Instant timestamp, int status, String error,
                            String reason, String message, String path) {
}
