/*
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements.  See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership.  The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License.  You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */
package org.apache.sling.jcr.resourcesecurity.impl;

import javax.jcr.RepositoryException;
import javax.jcr.Session;

import org.apache.sling.api.resource.Resource;
import org.apache.sling.api.resource.ResourceResolver;
import org.apache.sling.resourceaccesssecurity.AllowingResourceAccessGate;
import org.apache.sling.resourceaccesssecurity.ResourceAccessGate;
import org.osgi.service.component.annotations.Activate;
import org.osgi.service.component.annotations.Component;
import org.osgi.service.component.annotations.ConfigurationPolicy;
import org.osgi.service.metatype.annotations.AttributeDefinition;
import org.osgi.service.metatype.annotations.Designate;
import org.osgi.service.metatype.annotations.ObjectClassDefinition;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

@Component(configurationPolicy=ConfigurationPolicy.REQUIRE, service = ResourceAccessGate.class, property = {
        ResourceAccessGate.OPERATIONS+"=read",
        ResourceAccessGate.OPERATIONS+"=create",
        ResourceAccessGate.OPERATIONS+"=update",
        ResourceAccessGate.OPERATIONS+"=delete",
        ResourceAccessGate.OPERATIONS+"=order-children",
        ResourceAccessGate.CONTEXT+"="+ResourceAccessGate.PROVIDER_CONTEXT
})
@Designate(factory = true, ocd = ResourceAccessGateFactory.Configuration.class)
public class ResourceAccessGateFactory
    extends AllowingResourceAccessGate
    implements ResourceAccessGate {

    static final String PROP_JCR_PATH = "jcrPath";

    static final String PROP_PREFIX = "checkpath.prefix";

    private String jcrPath;

    private String prefix;
    
    private static final Logger LOGGER = LoggerFactory.getLogger(ResourceAccessGateFactory.class);

    @ObjectClassDefinition(
            name = "Apache Sling JCR Resource Access Gate",
            description = "This access gate can be used to handle the access to resources" +
                       " not backed by a JCR repository by leveraging ACLs in the " +
                       "JCR repository")
    public static @interface Configuration {
        @AttributeDefinition(name = "Path", description = "The path is a regular expression which must match the affected resource path for this service to be called.")
        String path() default ".*";
        @AttributeDefinition(name = "Deep Check Prefix", 
                description="If this value is configured and the resource path starts with this" +
                " prefix, the prefix is removed from the path and the remaining part is appended " +
                " to the JCR path to check. For example if /foo/a/b/c is required, this prefix is " +
                " configured with /foo and the JCR node to check is /check, the permissions at " +
                " /check/a/b/c are checked.")
        String checkpath_prefix();
        @AttributeDefinition(name = "JCR Node Path", description = "The node given through this path is consulted for granting/denying permissions to the resources. If 'Deep Check Prefix' is used, then this only specifies the node's path prefix.")
        String jcrPath();
    }

    @Activate
    protected void activate(Configuration configuration) {
        this.jcrPath = configuration.jcrPath();
        this.prefix = configuration.checkpath_prefix();
        if ( this.prefix != null && !this.prefix.endsWith("/") ) {
             this.prefix = this.prefix + "/";
        }
    }

    /**
     * Check the permission
     */
    private GateResult checkPermission(final ResourceResolver resolver,
            final String path,
            final String permission) {
        boolean granted = false;
        final Session session = resolver.adaptTo(Session.class);
        if ( session != null ) {
            String checkPath = this.jcrPath;
            if ( this.prefix != null && path.startsWith(this.prefix) ) {
                checkPath = this.jcrPath + path.substring(this.prefix.length() - 1);
            }
            try {
                granted = session.hasPermission(checkPath, permission);
            } catch (final RepositoryException re) {
                // ignore
                LOGGER.debug("Could not retrieve permission {} for path {}", checkPath, permission, re);
            }
        }
        return granted ? GateResult.GRANTED : GateResult.DENIED;
    }

    /**
     * @see org.apache.sling.resourceaccesssecurity.AllowingResourceAccessGate#hasReadRestrictions(org.apache.sling.api.resource.ResourceResolver)
     */
    @Override
    public boolean hasReadRestrictions(final ResourceResolver resourceResolver) {
        return true;
    }

    /**
     * @see org.apache.sling.resourceaccesssecurity.AllowingResourceAccessGate#hasCreateRestrictions(org.apache.sling.api.resource.ResourceResolver)
     */
    @Override
    public boolean hasCreateRestrictions(final ResourceResolver resourceResolver) {
        return true;
    }

    /**
     * @see org.apache.sling.resourceaccesssecurity.AllowingResourceAccessGate#hasReorderChildrenRestrictions(org.apache.sling.api.resource.ResourceResolver)
     */
    @Override
    public boolean hasOrderChildrenRestrictions(ResourceResolver resourceResolver) {
        return true;
    }

    /**
     * @see org.apache.sling.resourceaccesssecurity.AllowingResourceAccessGate#hasUpdateRestrictions(org.apache.sling.api.resource.ResourceResolver)
     */
    @Override
    public boolean hasUpdateRestrictions(final ResourceResolver resourceResolver) {
        return true;
    }

    /**
     * @see org.apache.sling.resourceaccesssecurity.AllowingResourceAccessGate#hasDeleteRestrictions(org.apache.sling.api.resource.ResourceResolver)
     */
    @Override
    public boolean hasDeleteRestrictions(final ResourceResolver resourceResolver) {
        return true;
    }

    
    /**
     * @see org.apache.sling.resourceaccesssecurity.AllowingResourceAccessGate#canRead(org.apache.sling.api.resource.Resource)
     */
    @Override
    public GateResult canRead(final Resource resource) {
        return this.checkPermission(resource.getResourceResolver(), resource.getPath(), Session.ACTION_READ);
    }

    /**
     * @see org.apache.sling.resourceaccesssecurity.AllowingResourceAccessGate#canDelete(org.apache.sling.api.resource.Resource)
     */
    @Override
    public GateResult canDelete(Resource resource) {
        return this.checkPermission(resource.getResourceResolver(), resource.getPath(), Session.ACTION_REMOVE);
    }

    /**
     * @see org.apache.sling.resourceaccesssecurity.AllowingResourceAccessGate#canUpdate(org.apache.sling.api.resource.Resource)
     */
    @Override
    public GateResult canUpdate(Resource resource) {
        return this.checkPermission(resource.getResourceResolver(), resource.getPath(), Session.ACTION_SET_PROPERTY);
    }

    /**
     * @see org.apache.sling.resourceaccesssecurity.AllowingResourceAccessGate#canCreate(java.lang.String, org.apache.sling.api.resource.ResourceResolver)
     */
    @Override
    public GateResult canCreate(String absPathName, ResourceResolver resourceResolver) {
        return this.checkPermission(resourceResolver, absPathName, Session.ACTION_ADD_NODE);
    }

    /**
     * @see org.apache.sling.resourceaccesssecurity.AllowingResourceAccessGate#canOrderChildren(Resource)
     */
    @Override
    public GateResult canOrderChildren(Resource resource) {
        return this.checkPermission(resource.getResourceResolver(), resource.getPath(), Session.ACTION_SET_PROPERTY);
    }
}
