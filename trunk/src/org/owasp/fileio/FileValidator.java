/**
 * This file is part of the Open Web Application Security Project (OWASP) Java File IO Security project. For details, please see
 * <a href="https://www.owasp.org/index.php/OWASP_Java_File_I_O_Security_Project">https://www.owasp.org/index.php/OWASP_Java_File_I_O_Security_Project</a>.
 *
 * Copyright (c) 2014 - The OWASP Foundation
 *
 * This API is published by OWASP under the Apache 2.0 license. You should read and accept the LICENSE before you use, modify, and/or redistribute this software.
 *
 * @author Jeff Williams <a href="http://www.aspectsecurity.com">Aspect Security</a> - Original ESAPI author 
 * @author Jim Manico (jim@manico.net) <a href="http://www.manico.net">Manico.net</a> - Original ESAPI author 
 * @author August Detlefsen <a href="http://www.codemagi.com">CodeMagi</a> - Java File IO Security Project lead
 * @created 2014
 */
package org.owasp.fileio;

import java.io.File;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Iterator;
import java.util.List;
import java.util.regex.Pattern;
import org.owasp.fileio.util.Utils;

/**
 * Reference implementation of the FileValidator. This implementation
 * provides basic validation functions. This library
 * has a heavy emphasis on whitelist validation and canonicalization.
 *
 * @author August Detlefsen <a href="http://www.codemagi.com">CodeMagi</a>
 */
public class FileValidator {

    // Validation of file related input
    public static final String FILE_NAME_REGEX = "^[a-zA-Z0-9!@#$%^&{}\\[\\]()_+\\-=,.~'` ]{1,255}$";
    public static final String DIRECTORY_NAME_REGEX = "^[a-zA-Z0-9:/\\\\!@#$%^&{}\\[\\]()_+\\-=,.~'` ]{1,255}$";
    
    /**
     * The encoder to use for file system
     */
    private Encoder fileEncoder;

    /**
     * The maximum allowable upload size 
     */
    private Long maxFileUploadSize = 500000000l;
    
    /**
     * The maximum allowable file path length
     */
    private Integer maxFilePathSize = 255;
    
    /**
     * The file extension that will be allowed by this validator
     */
    List<String> allowedExtensions = new ArrayList<String>();
    
    /**
     * Initialize file validator with an appropriate set of codecs
     */
    public FileValidator() {
	fileEncoder = new Encoder();
    }

    /**
     * Initialize file validator with an appropriate set of codecs
     * @param encoder
     */
    public FileValidator(Encoder encoder) {
	fileEncoder = encoder;
    }

    //GETTERS AND SETTERS --------------------------------------------------------------
    
    public Long getMaxFileUploadSize() {
	return maxFileUploadSize;
    }

    public void setMaxFileUploadSize(Long maxFileUploadSize) {
	this.maxFileUploadSize = maxFileUploadSize;
    }

    public List<String> getAllowedExtensions() {
	return allowedExtensions;
    }

    public void setAllowedExtensions(List<String> allowedExtensions) {
	this.allowedExtensions = allowedExtensions;
    }

    public Integer getMaxFilePathSize() {
	return maxFilePathSize;
    }

    public void setMaxFilePathSize(Integer maxFilePathSize) {
	this.maxFilePathSize = maxFilePathSize;
    }

    public Encoder getFileEncoder() {
	return fileEncoder;
    }

    public void setFileEncoder(Encoder fileEncoder) {
	this.fileEncoder = fileEncoder;
    }
    
    
    
    /**
     * Calls getValidDirectoryPath and returns true if no exceptions are thrown.
     *
     * <p><b>Note:</b> On platforms that support symlinks, this function will fail canonicalization if directorypath is a symlink. For example, on MacOS X, /etc is actually /private/etc. If you mean
     * to use /etc, use its real path (/private/etc), not the symlink (/etc).</p>
     * 
     * @param context
     * @param input
     * @param parent
     * @param allowNull
     * 
     * @return true if no validation exceptions are thrown
     */
    public boolean isValidDirectoryPath(String context, String input, File parent, boolean allowNull) {
	try {
	    getValidDirectoryPath(context, input, parent, allowNull);
	    return true;
	} catch (ValidationException e) {
	    return false;
	}
    }

    /**
     * Calls getValidDirectoryPath and returns true if no exceptions are thrown.
     *
     * <p><b>Note:</b> On platforms that support symlinks, this function will fail canonicalization if directorypath is a symlink. For example, on MacOS X, /etc is actually /private/etc. If you mean
     * to use /etc, use its real path (/private/etc), not the symlink (/etc).</p>
     * 
     * @param context A descriptive name of the parameter that you are validating (e.g., LoginPage_UsernameField). This value is used by any logging or error handling that is done with respect to the
     * value passed in.
     * @param input The actual input data to validate.
     * @param parent
     * @param allowNull If allowNull is true then an input that is NULL or an empty string will be legal. If allowNull is false then NULL or an empty String will throw a ValidationException.
     * @param errors
     * 
     * @return true if no validation exceptions are thrown
     */
    public boolean isValidDirectoryPath(String context, String input, File parent, boolean allowNull, List<ValidationException> errors) {
	try {
	    getValidDirectoryPath(context, input, parent, allowNull);
	    return true;
	} catch (ValidationException e) {
	    errors.add(e);
	}

	return false;
    }

    /**
     * Returns a canonicalized and validated directory path as a String, provided that the input maps to an existing directory that is an existing subdirectory (at any level) of the specified parent.
     * Invalid input will generate a descriptive ValidationException, and input that is clearly an attack will generate a descriptive IntrusionException. Instead of throwing a ValidationException on
     * error, this variant will store the exception inside of the ValidationErrorList.
     *
     * @param context A descriptive name of the parameter that you are validating (e.g., LoginPage_UsernameField). This value is used by any logging or error handling that is done with respect to the
     * value passed in.
     * @param input The actual input data to validate.
     * @param parent
     * @param allowNull If allowNull is true then an input that is NULL or an empty string will be legal. If allowNull is false then NULL or an empty String will throw a ValidationException.
     *
     * @return A valid directory path
     *
     * @throws ValidationException
     */
    public String getValidDirectoryPath(String context, String input, File parent, boolean allowNull) throws ValidationException {
	try {
	    if (Utils.isEmpty(input)) {
		if (allowNull) {
		    return null;
		}
		throw new ValidationException(context + ": Input directory path required", "Input directory path required: context=" + context + ", input=" + input, context);
	    }

	    File dir = new File(input);

	    // check dir exists and parent exists and dir is inside parent
	    if (!dir.exists()) {
		throw new ValidationException(context + ": Invalid directory name", "Invalid directory, does not exist: context=" + context + ", input=" + input);
	    }
	    if (!dir.isDirectory()) {
		throw new ValidationException(context + ": Invalid directory name", "Invalid directory, not a directory: context=" + context + ", input=" + input);
	    }
	    if (!parent.exists()) {
		throw new ValidationException(context + ": Invalid directory name", "Invalid directory, specified parent does not exist: context=" + context + ", input=" + input + ", parent=" + parent);
	    }
	    if (!parent.isDirectory()) {
		throw new ValidationException(context + ": Invalid directory name", "Invalid directory, specified parent is not a directory: context=" + context + ", input=" + input + ", parent=" + parent);
	    }
	    if (!dir.getCanonicalPath().startsWith(parent.getCanonicalPath())) {
		throw new ValidationException(context + ": Invalid directory name", "Invalid directory, not inside specified parent: context=" + context + ", input=" + input + ", parent=" + parent);
	    }

	    // check canonical form matches input
	    String canonicalPath = dir.getCanonicalPath();
	    String canonical = getValidInput(context, canonicalPath, DIRECTORY_NAME_REGEX, maxFilePathSize, false);
	    if (!canonical.equals(input)) {
		throw new ValidationException(context + ": Invalid directory name", "Invalid directory name does not match the canonical path: context=" + context + ", input=" + input + ", canonical=" + canonical, context);
	    }
	    return canonical;
	} catch (Exception e) {
	    throw new ValidationException(context + ": Invalid directory name", "Failure to validate directory path: context=" + context + ", input=" + input, e, context);
	}
    }

    /**
     * Calls getValidDirectoryPath with the supplied error List to capture ValidationExceptions
     * 
     * @param context
     * @param input
     * @param parent
     * @param allowNull
     * @param errors 
     * 
     * @return 
     */
    public String getValidDirectoryPath(String context, String input, File parent, boolean allowNull, List<ValidationException> errors) {

	try {
	    return getValidDirectoryPath(context, input, parent, allowNull);
	} catch (ValidationException e) {
	    errors.add(e);
	}

	return "";
    }

    /**
     * Calls getValidFileName with the default list of allowedExtensions
     * 
     * @param context
     * @param input
     * @param allowNull
     * 
     * @return true if no validation exceptions occur
     */
    public boolean isValidFileName(String context, String input, boolean allowNull) {
	return isValidFileName(context, input, null, allowNull);
    }

    /**
     * Calls getValidFileName with the default list of allowedExtensions
     * 
     * @param context
     * @param input
     * @param allowNull
     * @param errors
     * 
     * @return true if no validation exceptions occur
     */
    public boolean isValidFileName(String context, String input, boolean allowNull, List<ValidationException> errors) {
	return isValidFileName(context, input, null, allowNull, errors);
    }

    /**
     * Calls getValidFileName with the default list of allowedExtensions
     * 
     * @param context
     * @param input
     * @param allowedExtensions
     * @param allowNull
     * 
     * @return true if no validation exceptions occur
     */
    public boolean isValidFileName(String context, String input, List<String> allowedExtensions, boolean allowNull) {
	try {
	    getValidFileName(context, input, allowedExtensions, allowNull);
	    return true;
	} catch (Exception e) {
	    return false;
	}
    }

    /**
     * Calls getValidFileName with the default list of allowedExtensions
     * 
     * @param context
     * @param input
     * @param allowedExtensions
     * @param allowNull
     * @param errors
     * 
     * @return true if no validation exceptions occur
     */
    public boolean isValidFileName(String context, String input, List<String> allowedExtensions, boolean allowNull, List<ValidationException> errors) {
	try {
	    getValidFileName(context, input, allowedExtensions, allowNull);
	    return true;
	} catch (ValidationException e) {
	    errors.add(e);
	}

	return false;
    }

    /**
     * Returns a canonicalized and validated file name as a String. Implementors should check for allowed file extensions here, as well as allowed file name characters, as declared in
     * "ESAPI.properties". Invalid input will generate a descriptive ValidationException, and input that is clearly an attack will generate a descriptive IntrusionException.
     *
     * Note: If you do not explicitly specify a white list of allowed extensions, all extensions will be allowed by default.
     *
     * @param context A descriptive name of the parameter that you are validating (e.g., LoginPage_UsernameField). This value is used by any logging or error handling that is done with respect to the
     * value passed in.
     * @param input The actual input data to validate.
     * @param allowedExtensions
     * @param allowNull If allowNull is true then an input that is NULL or an empty string will be legal. If allowNull is false then NULL or an empty String will throw a ValidationException.
     *
     * @return A valid file name
     *
     * @throws ValidationException
     */
    public String getValidFileName(String context, String input, List<String> allowedExtensions, boolean allowNull) throws ValidationException {

	String canonical = "";
	// detect path manipulation
	try {
	    if (Utils.isEmpty(input)) {
		if (allowNull) {
		    return null;
		}
		throw new ValidationException(context + ": Input file name required", "Input required: context=" + context + ", input=" + input, context);
	    }

	    // do basic validation
	    canonical = new File(input).getCanonicalFile().getName();
	    getValidInput(context, input, FILE_NAME_REGEX, 255, true);

	    File f = new File(canonical);
	    String c = f.getCanonicalPath();
	    String cpath = c.substring(c.lastIndexOf(File.separator) + 1);


	    // the path is valid if the input matches the canonical path
	    if (!input.equals(cpath)) {
		throw new ValidationException(context + ": Invalid file name", "Invalid directory name does not match the canonical path: context=" + context + ", input=" + input + ", canonical=" + canonical, context);
	    }

	} catch (IOException e) {
	    throw new ValidationException(context + ": Invalid file name", "Invalid file name does not exist: context=" + context + ", canonical=" + canonical, e, context);
	}

	// verify extensions
	if ((allowedExtensions == null) || (allowedExtensions.isEmpty())) {
	    return canonical;
	} else {
	    Iterator<String> i = allowedExtensions.iterator();
	    while (i.hasNext()) {
		String ext = i.next();
		if (input.toLowerCase().endsWith(ext.toLowerCase())) {
		    return canonical;
		}
	    }
	    throw new ValidationException(context + ": Invalid file name does not have valid extension ( " + allowedExtensions + ")", "Invalid file name does not have valid extension ( " + allowedExtensions + "): context=" + context + ", input=" + input, context);
	}
    }

    /**
     * Calls getValidFileName with the supplied List to capture ValidationExceptions
     * 
     * @param context
     * @param input
     * @param allowedParameters
     * @param allowNull
     * @param errors
     * 
     * @return 
     */
    public String getValidFileName(String context, String input, List<String> allowedParameters, boolean allowNull, List<ValidationException> errors) {
	try {
	    return getValidFileName(context, input, allowedParameters, allowNull);
	} catch (ValidationException e) {
	    errors.add(e);
	}

	return "";
    }

    /**
     * Calls getValidFileUpload and returns true if no exceptions are thrown.
     *
     * <p><b>Note:</b> On platforms that support symlinks, this function will fail canonicalization if directorypath is a symlink. For example, on MacOS X, /etc is actually /private/etc. If you mean
     * to use /etc, use its real path (/private/etc), not the symlink (/etc).</p>
     * 
     * @param context
     * @param directorypath
     * @param filename
     * @param parent
     * @param content
     * @param maxBytes
     * @param allowNull
     * 
     * @return true if no validation exceptions are thrown
     * 
     * @throws org.owasp.fileio.ValidationException
     */
    public boolean isValidFileUpload(String context, String directorypath, String filename, File parent, byte[] content, int maxBytes, boolean allowNull) throws ValidationException {
	return (isValidFileName(context, filename, allowNull)
		&& isValidDirectoryPath(context, directorypath, parent, allowNull)
		&& isValidFileContent(context, content, maxBytes, allowNull));
    }

    /**
     * Calls getValidFileUpload and returns true if no exceptions are thrown.
     *
     * <p><b>Note:</b> On platforms that support symlinks, this function will fail canonicalization if directorypath is a symlink. For example, on MacOS X, /etc is actually /private/etc. If you mean
     * to use /etc, use its real path (/private/etc), not the symlink (/etc).</p>
     * 
     * @param context A descriptive name of the parameter that you are validating (e.g., LoginPage_UsernameField). This value is used by any logging or error handling that is done with respect to the
     * value passed in.
     * @param directorypath
     * @param filename
     * @param parent
     * @param content
     * @param maxBytes
     * @param allowNull If allowNull is true then an input that is NULL or an empty string will be legal. If allowNull is false then NULL or an empty String will throw a ValidationException.
     * @param errors
     * 
     * @return true if no validation exceptions are thrown
     */
    public boolean isValidFileUpload(String context, String directorypath, String filename, File parent, byte[] content, int maxBytes, boolean allowNull, List<ValidationException> errors) {
	return (isValidFileName(context, filename, allowNull, errors)
		&& isValidDirectoryPath(context, directorypath, parent, allowNull, errors)
		&& isValidFileContent(context, content, maxBytes, allowNull, errors));
    }

    /**
     * Validates the filepath, filename, and content of a file. Invalid input will generate a descriptive ValidationException.
     *
     * @param context A descriptive name of the parameter that you are validating (e.g., LoginPage_UsernameField). This value is used by any logging or error handling that is done with respect to the
     * value passed in.
     * @param directorypath The file path of the uploaded file.
     * @param filename The filename of the uploaded file
     * @param parent
     * @param content A byte array containing the content of the uploaded file.
     * @param maxBytes The max number of bytes allowed for a legal file upload.
     * @param allowedExtensions
     * @param allowNull If allowNull is true then an input that is NULL or an empty string will be legal. If allowNull is false then NULL or an empty String will throw a ValidationException.
     *
     * @throws ValidationException
     */
    public void assertValidFileUpload(String context, String directorypath, String filename, File parent, byte[] content, int maxBytes, List<String> allowedExtensions, boolean allowNull) throws ValidationException {
	getValidFileName(context, filename, allowedExtensions, allowNull);
	getValidDirectoryPath(context, directorypath, parent, allowNull);
	getValidFileContent(context, content, maxBytes, allowNull);
    }

    /**
     * Calls getValidFileUpload with the supplied List to capture ValidationExceptions
     * 
     * @param context
     * @param filepath
     * @param filename
     * @param parent
     * @param content
     * @param maxBytes
     * @param allowedExtensions
     * @param allowNull
     * @param errors
     */
    public void assertValidFileUpload(String context, String filepath, String filename, File parent, byte[] content, int maxBytes, List<String> allowedExtensions, boolean allowNull, List<ValidationException> errors) {
	try {
	    assertValidFileUpload(context, filepath, filename, parent, content, maxBytes, allowedExtensions, allowNull);
	} catch (ValidationException e) {
	    errors.add(e);
	}
    }

    /**
     * Calls getValidFileContent and returns true if no exceptions are thrown.
     * 
     * @param context
     * @param input
     * @param maxBytes
     * @param allowNull
     * 
     * @return true if no validation exceptions occur
     */
    public boolean isValidFileContent(String context, byte[] input, int maxBytes, boolean allowNull) {
	try {
	    getValidFileContent(context, input, maxBytes, allowNull);
	    return true;
	} catch (Exception e) {
	    return false;
	}
    }

    /**
     * Calls getValidFileContent and returns true if no exceptions are thrown.
     * 
     * @param context
     * @param input
     * @param maxBytes
     * @param allowNull
     * @param errors
     * 
     * @return true if no validation exceptions occur
     */
    public boolean isValidFileContent(String context, byte[] input, int maxBytes, boolean allowNull, List<ValidationException> errors) {
	try {
	    getValidFileContent(context, input, maxBytes, allowNull);
	    return true;
	} catch (ValidationException e) {
	    errors.add(e);
	    return false;
	}
    }

    /**
     * Returns validated file content as a byte array. This method checks for max file size (according to the value configured in the maxFileUploadSize class variable) 
     * and null input ONLY. It can be extended to check for allowed character sets, and do virus scans. Invalid
     * input will generate a descriptive ValidationException.
     *
     * @param context A descriptive name of the parameter that you are validating (e.g., LoginPage_UsernameField). This value is used by any logging or error handling that is done with respect to the
     * value passed in.
     * @param input The actual input data to validate.
     * @param allowNull If allowNull is true then an input that is NULL or an empty string will be legal. If allowNull is false then NULL or an empty String will throw a ValidationException.
     *
     * @return A byte array containing valid file content.
     *
     * @throws ValidationException
     */
    public byte[] getValidFileContent(String context, byte[] input, boolean allowNull) throws ValidationException {
	return getValidFileContent(context, input, getMaxFileUploadSize(), allowNull);
    }
	
    /**
     * Returns validated file content as a byte array. This method checks for max file size and null input ONLY. It can be extended to check for allowed character sets, and do virus scans. Invalid
     * input will generate a descriptive ValidationException.
     *
     * @param context A descriptive name of the parameter that you are validating (e.g., LoginPage_UsernameField). This value is used by any logging or error handling that is done with respect to the
     * value passed in.
     * @param input The actual input data to validate.
     * @param maxBytes The maximum number of bytes allowed in a legal file.
     * @param allowNull If allowNull is true then an input that is NULL or an empty string will be legal. If allowNull is false then NULL or an empty String will throw a ValidationException.
     *
     * @return A byte array containing valid file content.
     *
     * @throws ValidationException
     */
    public byte[] getValidFileContent(String context, byte[] input, long maxBytes, boolean allowNull) throws ValidationException {
	if (Utils.isEmpty(input)) {
	    if (allowNull) {
		return null;
	    }
	    throw new ValidationException(context + ": Input required", "Input required: context=" + context + ", input=" + Arrays.toString(input), context);
	}

	if (input.length > maxBytes) {
	    throw new ValidationException(context + ": Invalid file content can not exceed " + maxBytes + " bytes", "Exceeded maxBytes ( " + input.length + ")", context);
	}

	return input;
    }

    /**
     * Calls getValidFileContent with the supplied List to capture ValidationExceptions
     * 
     * @param context
     * @param input
     * @param maxBytes
     * @param allowNull
     * @param errors
     * 
     * @return 
     * 
     * @throws org.owasp.fileio.ValidationException
     */
    public byte[] getValidFileContent(String context, byte[] input, int maxBytes, boolean allowNull, List<ValidationException> errors) throws ValidationException {
	try {
	    return getValidFileContent(context, input, maxBytes, allowNull);
	} catch (ValidationException e) {
	    errors.add(e);
	}
	// return empty byte array on error
	return new byte[0];
    }

    /**
     * Validates data received from the browser and returns a safe version. Double encoding is treated as an attack. The default encoder supports html encoding, URL encoding, and javascript escaping.
     * Input is canonicalized by default before validation.
     *
     * @param context A descriptive name for the field to validate. This is used for error facing validation messages and element identification.
     * @param input The actual user input data to validate.
     * @param type The regular expression name which maps to the actual regular expression from "ESAPI.properties".
     * @param maxLength The maximum post-canonicalized String length allowed.
     * @param allowNull If allowNull is true then a input that is NULL or an empty string will be legal. If allowNull is false then NULL or an empty String will throw a ValidationException.
     * 
     * @return The canonicalized user input.
     * 
     * @throws ValidationException
     */
    public String getValidInput(String context, String input, String type, int maxLength, boolean allowNull) throws ValidationException {
	return getValidInput(context, input, type, maxLength, allowNull, true);
    }

    /**
     * Validates data received from the browser and returns a safe version. Only URL encoding is supported. Double encoding is treated as an attack.
     *
     * @param context A descriptive name for the field to validate. This is used for error facing validation messages and element identification.
     * @param input The actual user input data to validate.
     * @param type The regular expression name which maps to the actual regular expression in the ESAPI validation configuration file
     * @param maxLength The maximum String length allowed. If input is canonicalized per the canonicalize argument, then maxLength must be verified after canonicalization
     * @param allowNull If allowNull is true then a input that is NULL or an empty string will be legal. If allowNull is false then NULL or an empty String will throw a ValidationException.
     * @param canonicalize If canonicalize is true then input will be canonicalized before validation
     * 
     * @return The user input, may be canonicalized if canonicalize argument is true
     * 
     * @throws ValidationException
     */
    public String getValidInput(String context, String input, String type, int maxLength, boolean allowNull, boolean canonicalize) throws ValidationException {
	StringValidationRule rvr = new StringValidationRule(type, fileEncoder);

	Pattern p = Pattern.compile(type);
	rvr.addWhitelistPattern( p );

	rvr.setMaximumLength(maxLength);
	rvr.setAllowNull(allowNull);
	rvr.setValidateInputAndCanonical(canonicalize);
	return rvr.getValid(context, input);
    }
    
}