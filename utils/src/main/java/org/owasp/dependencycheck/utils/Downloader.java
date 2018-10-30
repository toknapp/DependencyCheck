/*
 * This file is part of dependency-check-core.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 * Copyright (c) 2012 Jeremy Long. All Rights Reserved.
 */
package org.owasp.dependencycheck.utils;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.URL;
import java.security.InvalidAlgorithmParameterException;
import static java.lang.String.format;
import org.apache.commons.io.IOUtils;

/**
 * A utility to download files from the Internet.
 *
 * @author Jeremy Long
 */
public final class Downloader {

    /**
     * The logger.
     */
    private static final Logger LOGGER = LoggerFactory.getLogger(Downloader.class);
    /**
     * The configured settings.
     */
    private final Settings settings;

    /**
     * The URL connection factory.
     */
    private final URLConnectionFactory connFactory;

    /**
     * Constructs a new Downloader object.
     *
     * @param settings the configured settings
     */
    public Downloader(Settings settings) {
        this.settings = settings;
        this.connFactory = new URLConnectionFactory(settings);
    }

    /**
     * Retrieves a file from a given URL and saves it to the outputPath.
     *
     * @param url the URL of the file to download
     * @param outputPath the path to the save the file to
     * @throws DownloadFailedException is thrown if there is an error
     * downloading the file
     */
    public void fetchFile(URL url, File outputPath) throws DownloadFailedException {
        fetchFile(url, outputPath, true);
    }

    /**
     * Retrieves a file from a given URL and saves it to the outputPath.
     *
     * @param url the URL of the file to download
     * @param outputPath the path to the save the file to
     * @param useProxy whether to use the configured proxy when downloading
     * files
     * @throws DownloadFailedException is thrown if there is an error
     * downloading the file
     */
    public void fetchFile(URL url, File outputPath, boolean useProxy) throws DownloadFailedException {
        try (HttpResourceConnection conn = new HttpResourceConnection(settings, useProxy);
                OutputStream out = new FileOutputStream(outputPath)) {
            InputStream in = conn.fetch(url);
            IOUtils.copy(in, out);
        } catch (IOException ex) {
            final String msg = format("Download failed, unable to copy '%s' to '%s'", url.toString(), outputPath.getAbsolutePath());
            throw new DownloadFailedException(msg, ex);
        }
    }

    /**
     * Analyzes the IOException, logs the appropriate information for debugging
     * purposes, and then throws a DownloadFailedException that wraps the IO
     * Exception for common IO Exceptions. This is to provide additional details
     * to assist in resolution of the exception.
     *
     * @param ex the original exception
     * @throws DownloadFailedException a wrapper exception that contains the
     * original exception as the cause
     */
    protected void checkForCommonExceptionTypes(IOException ex) throws DownloadFailedException {
        Throwable cause = ex;
        while (cause != null) {
            if (cause instanceof java.net.UnknownHostException) {
                final String msg = format("Unable to resolve domain '%s'", cause.getMessage());
                LOGGER.error(msg);
                throw new DownloadFailedException(msg, cause);
            }
            if (cause instanceof InvalidAlgorithmParameterException) {
                final String keystore = System.getProperty("javax.net.ssl.keyStore");
                final String version = System.getProperty("java.version");
                final String vendor = System.getProperty("java.vendor");
                LOGGER.info("Error making HTTPS request - InvalidAlgorithmParameterException");
                LOGGER.info("There appears to be an issue with the installation of Java and the cacerts."
                        + "See closed issue #177 here: https://github.com/jeremylong/DependencyCheck/issues/177");
                LOGGER.info("Java Info:\njavax.net.ssl.keyStore='{}'\njava.version='{}'\njava.vendor='{}'",
                        keystore, version, vendor);
                throw new DownloadFailedException("Error making HTTPS request. Please see the log for more details.");
            }
            cause = cause.getCause();
        }
    }
}
