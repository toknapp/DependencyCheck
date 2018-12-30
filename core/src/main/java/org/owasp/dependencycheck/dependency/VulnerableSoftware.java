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
 * Copyright (c) 2018 Jeremy Long. All Rights Reserved.
 */
package org.owasp.dependencycheck.dependency;

import java.io.Serializable;

import javax.annotation.concurrent.ThreadSafe;

import org.apache.commons.lang3.builder.CompareToBuilder;
import org.apache.commons.lang3.builder.EqualsBuilder;
import org.apache.commons.lang3.builder.HashCodeBuilder;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import us.springett.parsers.cpe.Cpe;
import us.springett.parsers.cpe.ICpe;
import us.springett.parsers.cpe.exceptions.CpeValidationException;
import us.springett.parsers.cpe.values.Part;

/**
 * A record containing information about vulnerable software. This is referenced
 * from a vulnerability.
 *
 * @author Jeremy Long
 */
@ThreadSafe
public class VulnerableSoftware extends Cpe implements Serializable {

    /**
     * The logger.
     */
    private static final Logger LOGGER = LoggerFactory.getLogger(VulnerableSoftware.class);
    /**
     * The serial version UID.
     */
    private static final long serialVersionUID = 605319412326651052L;

    /**
     * The ending range, excluding the specified version, for matching
     * vulnerable software
     */
    private final String versionEndExcluding;
    /**
     * The ending range, including the specified version, for matching
     * vulnerable software
     */
    private final String versionEndIncluding;
    /**
     * The starting range, excluding the specified version, for matching
     * vulnerable software
     */
    private final String versionStartExcluding;
    /**
     * the starting range, including the specified version, for matching
     * vulnerable software
     */
    private final String versionStartIncluding;
    /**
     * A flag indicating whether this represents a vulnerable software object.
     */
    private final boolean vulnerable;

    /**
     * Constructs a new immutable VulnerableSoftware object that represents the
     * Well Form Named defined in the CPE 2.3 specification. Specifying
     * <code>null</code> will be set to the default
     * {@link us.springett.parsers.cpe.values.LogicalValue#ANY}. All values
     * passed in must be well formed (i.e. special characters quoted with a
     * backslash).
     *
     * @see <a href="https://cpe.mitre.org/specification/">CPE 2.3</a>
     * @param part the type of entry: application, operating system, or hardware
     * @param vendor the vendor of the CPE entry
     * @param product the product of the CPE entry
     * @param version the version of the CPE entry
     * @param update the update of the CPE entry
     * @param edition the edition of the CPE entry
     * @param language the language of the CPE entry
     * @param swEdition the swEdition of the CPE entry
     * @param targetSw the targetSw of the CPE entry
     * @param targetHw the targetHw of the CPE entry
     * @param other the other of the CPE entry
     * @param versionEndExcluding the ending range, excluding the specified
     * version, for matching vulnerable software
     * @param versionEndIncluding the ending range, including the specified
     * version, for matching vulnerable software
     * @param versionStartExcluding the starting range, excluding the specified
     * version, for matching vulnerable software
     * @param versionStartIncluding the starting range, including the specified
     * version, for matching vulnerable software
     * @param vulnerable whether or not this represents a vulnerable software
     * item
     * @throws CpeValidationException thrown if one of the CPE entries is
     * invalid
     */
    public VulnerableSoftware(Part part, String vendor, String product, String version,
            String update, String edition, String language, String swEdition,
            String targetSw, String targetHw, String other,
            String versionEndExcluding, String versionEndIncluding, String versionStartExcluding,
            String versionStartIncluding, boolean vulnerable) throws CpeValidationException {
        super(part, vendor, product, version, update, edition, language, swEdition, targetSw, targetHw, other);
        this.versionEndExcluding = versionEndExcluding;
        this.versionEndIncluding = versionEndIncluding;
        this.versionStartExcluding = versionStartExcluding;
        this.versionStartIncluding = versionStartIncluding;
        this.vulnerable = vulnerable;
    }

    @Override
    public int compareTo(Object o) {
        if (o instanceof VulnerableSoftware) {
            VulnerableSoftware other = (VulnerableSoftware) o;
            return new CompareToBuilder()
                    .appendSuper(super.compareTo(other))
                    .append(versionStartIncluding, other.versionStartIncluding)
                    .append(versionStartExcluding, other.versionStartExcluding)
                    .append(versionEndIncluding, other.versionEndIncluding)
                    .append(versionEndExcluding, other.versionEndExcluding)
                    .append(this.vulnerable, other.vulnerable)
                    .build();
        } else if (o instanceof Cpe) {
            return super.compareTo(o);
        }
        throw new RuntimeException("Unable to compare " + o.getClass().getCanonicalName());
    }

    @Override
    public int hashCode() {
        // you pick a hard-coded, randomly chosen, non-zero, odd number
        // ideally different for each class
        return new HashCodeBuilder(13, 59)
                .appendSuper(super.hashCode())
                .append(versionEndExcluding)
                .append(versionEndIncluding)
                .append(versionStartExcluding)
                .append(versionStartIncluding)
                .toHashCode();
    }

    @Override
    public boolean equals(Object obj) {
        if (obj == null) {
            return false;
        }
        if (obj == this) {
            return true;
        }
        if (obj.getClass() != getClass()) {
            return false;
        }
        VulnerableSoftware rhs = (VulnerableSoftware) obj;
        return new EqualsBuilder()
                .appendSuper(super.equals(obj))
                .append(versionEndExcluding, rhs.versionEndExcluding)
                .append(versionEndIncluding, rhs.versionEndIncluding)
                .append(versionStartExcluding, rhs.versionStartExcluding)
                .append(versionStartIncluding, rhs.versionStartIncluding)
                .isEquals();
    }

    /**
     * <p>
     * Determines if the VulnerableSoftware matches the given target
     * VulnerableSoftware. This does not follow the CPE 2.3 Specification
     * exactly as there are cases where undefined comparisons will result in
     * either true or false. For instance, 'ANY' will match 'm+wild cards' and
     * NA will return false when the target has 'm+wild cards'.</p>
     * <p>
     * For vulnerable software matching, the implementation also takes into
     * account version ranges as specified within the NVD data feeds.</p>
     *
     * @param target the target CPE to evaluate
     * @return <code>true</code> if the CPE matches the target; otherwise
     * <code>false</code>
     */
    @Override
    public boolean matches(ICpe target) {
        boolean result = true;
        result &= compareAttributes(this.getPart(), target.getPart());
        result &= compareAttributes(this.getVendor(), target.getVendor());
        result &= compareAttributes(this.getProduct(), target.getProduct());

        //TODO implement versionStart etc.
        result &= compareAttributes(this.getVersion(), target.getVersion());
        result &= compareAttributes(this.getUpdate(), target.getUpdate());
        
        result &= compareAttributes(this.getEdition(), target.getEdition());
        result &= compareAttributes(this.getLanguage(), target.getLanguage());
        result &= compareAttributes(this.getSwEdition(), target.getSwEdition());
        result &= compareAttributes(this.getTargetSw(), target.getTargetSw());
        result &= compareAttributes(this.getTargetHw(), target.getTargetHw());
        result &= compareAttributes(this.getOther(), target.getOther());
        return result;
    }

    /**
     * <p>
     * Determines if the target VulnerableSoftware matches the
     * VulnerableSoftware. This does not follow the CPE 2.3 Specification
     * exactly as there are cases where undefined comparisons will result in
     * either true or false. For instance, 'ANY' will match 'm+wild cards' and
     * NA will return false when the target has 'm+wild cards'.</p>
     * <p>
     * For vulnerable software matching, the implementation also takes into
     * account version ranges as specified within the NVD data feeds.</p>
     *
     * @param target the VulnerableSoftware to evaluate
     * @return <code>true</code> if the target CPE matches CPE; otherwise
     * <code>false</code>
     */
    @Override
    public boolean matchedBy(ICpe target) {
        return target.matches(this);
    }
}
