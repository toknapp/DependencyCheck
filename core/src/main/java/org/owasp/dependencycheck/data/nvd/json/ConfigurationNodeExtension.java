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
package org.owasp.dependencycheck.data.nvd.json;

import java.util.stream.Stream;

/**
 * A simple wrapper around the generated NVD CVE JSON Node object
 * to allow for streaming of the entire hierarchy of nodes.
 * 
 * Solution from https://stackoverflow.com/a/32657784/1995422
 * 
 * @author Jeremy Long
 */
public class ConfigurationNodeExtension extends Node {
    public ConfigurationNodeExtension(Node node) {
        this.setChildren(node.getChildren());
        this.setNegate(node.getNegate());
        this.setOperator(node.getOperator());
    }
    
    public Stream<CpeMatch> streamCpeMatches() {
        return this.getCpeMatch().stream();
    }
    
    public Stream<ConfigurationNodeExtension> streamNodes() {
        return Stream.concat(Stream.of(this), subNodes().flatMap(ConfigurationNodeExtension::streamNodes));
    }

    private Stream<ConfigurationNodeExtension> subNodes() {
        return getChildren().stream().map(o -> new ConfigurationNodeExtension(o));
    }
}
