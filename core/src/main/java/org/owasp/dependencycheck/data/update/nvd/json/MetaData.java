/*
 * Copyright 2018 OWASP.
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
package org.owasp.dependencycheck.data.update.nvd.json;

import com.google.gson.annotations.SerializedName;

/**
 *
 * @author jeremy
 */
class MetaData {
    
    /**
     * The CVE ID.
     */
    @SerializedName("ID")
    private String cveId;

    /**
     * Get the value of cveId
     *
     * @return the value of cveId
     */
    public String getCveId() {
        return cveId;
    }

    /**
     * Set the value of cveId
     *
     * @param cveId new value of cveId
     */
    public void setCveId(String cveId) {
        this.cveId = cveId;
    }
}
