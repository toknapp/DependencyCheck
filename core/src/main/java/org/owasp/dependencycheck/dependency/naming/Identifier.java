/*
 * Copyright 2019 OWASP.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.owasp.dependencycheck.dependency.naming;

import org.owasp.dependencycheck.dependency.Confidence;

/**
 *
 * @author jeremy
 */
public interface Identifier extends Comparable<Identifier> {

    /**
     * Get the value of confidence.
     *
     * @return the value of confidence
     */
    Confidence getConfidence();

    /**
     * Set the value of confidence.
     *
     * @param confidence the value of confidence
     */
    void setConfidence(Confidence confidence);

    /**
     * Get the value of URL.
     *
     * @return the value of URL
     */
    String getUrl();

    /**
     * Set the value of URL.
     *
     * @param url the value of URL
     */
    void setUrl(String url);

    /**
     * Get the value of notes from suppression notes.
     *
     * @return the value of notes
     */
    String getNotes();

    /**
     * Get the string representation of the Identifier.
     *
     * @return the value of notes
     */
    String getValue();

    /**
     * Set the value of notes.
     *
     * @param notes new value of notes
     */
    void setNotes(String notes);

}
