/**
 * This file is part of the Open Web Application Security Project (OWASP) Java File IO Security project. For details, please see
 * <a href="https://www.owasp.org/index.php/OWASP_Java_File_I_O_Security_Project">https://www.owasp.org/index.php/OWASP_Java_File_I_O_Security_Project</a>.
 *
 * Copyright (c) 2014 - The OWASP Foundation
 *
 * This API is published by OWASP under the Apache 2.0 license. You should read and accept the LICENSE before you use, modify, and/or redistribute this software.
 *
 * @author Jeff Williams <a href="http://www.aspectsecurity.com">Aspect Security</a> - Original ESAPI author
 * @author August Detlefsen <a href="http://www.codemagi.com">CodeMagi</a> - Java File IO Security Project lead
 * @created 2014
 */
package org.owasp.fileio;

/**
 * A ValidationException should be thrown to indicate that the data provided by the user or from some other external source does not match the validation rules that have been specified for that data.
 */
public class ValidationException extends Exception {

    protected static final long serialVersionUID = 1L;
    /**
     * The UI reference that caused this ValidationException
     */
    private String context;
    /**
     *
     */
    protected String logMessage = null;

    /**
     * Instantiates a new validation exception.
     */
    protected ValidationException() {
	// hidden
    }

    /**
     * Creates a new instance of ValidationException.
     *
     * @param userMessage the message to display to users
     * @param logMessage the message logged
     */
    public ValidationException(String userMessage, String logMessage) {
	super(userMessage);
	this.logMessage = logMessage;
    }

    /**
     * Instantiates a new ValidationException.
     *
     * @param userMessage the message to display to users
     * @param logMessage the message logged
     * @param cause the cause
     */
    public ValidationException(String userMessage, String logMessage, Throwable cause) {
	super(userMessage, cause);
	this.logMessage = logMessage;
    }

    /**
     * Creates a new instance of ValidationException.
     *
     * @param userMessage the message to display to users
     * @param logMessage the message logged
     * @param context the source that caused this exception
     */
    public ValidationException(String userMessage, String logMessage, String context) {
	super(userMessage);
	this.logMessage = logMessage;
	setContext(context);
    }

    /**
     * Instantiates a new ValidationException.
     *
     * @param userMessage the message to display to users
     * @param logMessage the message logged
     * @param cause the cause
     * @param context the source that caused this exception
     */
    public ValidationException(String userMessage, String logMessage, Throwable cause, String context) {
	super(userMessage, cause);
	this.logMessage = logMessage;
	setContext(context);
    }

    /**
     * Returns the UI reference that caused this ValidationException
     *
     * @return context, the source that caused the exception, stored as a string
     */
    public String getContext() {
	return context;
    }

    /**
     * Set's the UI reference that caused this ValidationException
     *
     * @param context the context to set, passed as a String
     */
    protected void setContext(String context) {
	this.context = context;
    }

    /**
     * Returns the UI reference that caused this ValidationException
     *
     * @return context, the source that caused the exception, stored as a string
     */
    public String getLogMessage() {
	return logMessage;
    }
}
