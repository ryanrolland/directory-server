/*
 *  Licensed to the Apache Software Foundation (ASF) under one
 *  or more contributor license agreements.  See the NOTICE file
 *  distributed with this work for additional information
 *  regarding copyright ownership.  The ASF licenses this file
 *  to you under the Apache License, Version 2.0 (the
 *  "License"); you may not use this file except in compliance
 *  with the License.  You may obtain a copy of the License at
 * 
 *    http://www.apache.org/licenses/LICENSE-2.0
 * 
 *  Unless required by applicable law or agreed to in writing,
 *  software distributed under the License is distributed on an
 *  "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 *  KIND, either express or implied.  See the License for the
 *  specific language governing permissions and limitations
 *  under the License.
 * 
 */
package org.apache.directory.server.core.memberof;


import org.apache.directory.api.ldap.model.constants.Loggers;
import org.apache.directory.api.ldap.model.entry.Entry;
import org.apache.directory.api.ldap.model.entry.Value;
import org.apache.directory.api.ldap.model.exception.LdapException;
import org.apache.directory.api.ldap.model.exception.LdapInvalidAttributeValueException;
import org.apache.directory.api.ldap.model.exception.LdapInvalidDnException;
import org.apache.directory.api.ldap.model.exception.LdapOperationException;
import org.apache.directory.api.ldap.model.exception.LdapOtherException;
import org.apache.directory.api.ldap.model.filter.EqualityNode;
import org.apache.directory.api.ldap.model.filter.ExprNode;
import org.apache.directory.api.ldap.model.message.AliasDerefMode;
import org.apache.directory.api.ldap.model.message.SearchScope;
import org.apache.directory.api.ldap.model.name.Dn;
import org.apache.directory.api.ldap.model.schema.AttributeType;
import org.apache.directory.api.ldap.model.schema.LdapSyntax;
import org.apache.directory.api.ldap.model.schema.syntaxCheckers.DirectoryStringSyntaxChecker;
import org.apache.directory.server.core.api.CoreSession;
import org.apache.directory.server.core.api.InterceptorEnum;
import org.apache.directory.server.core.api.filtering.EntryFilter;
import org.apache.directory.server.core.api.filtering.EntryFilteringCursor;
import org.apache.directory.server.core.api.interceptor.BaseInterceptor;
import org.apache.directory.server.core.api.interceptor.context.LookupOperationContext;
import org.apache.directory.server.core.api.interceptor.context.SearchOperationContext;
import org.apache.directory.server.core.api.partition.Partition;
import org.apache.directory.server.core.api.partition.PartitionNexus;
import org.apache.directory.server.core.api.partition.PartitionTxn;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;


/**
 * An interceptor for adding virtual memberOf attributes to {code}Entry{code}s.
 * 
 *
 * @author <a href="mailto:dev@directory.apache.org">Apache Directory Project</a>
 */
public class MemberOfInterceptor extends BaseInterceptor
{
    /** A aggregating logger */
    private static final Logger OPERATION_STATS = LoggerFactory.getLogger( Loggers.OPERATION_STAT.getName() );

    /** An operation logger */
    private static final Logger OPERATION_TIME = LoggerFactory.getLogger( Loggers.OPERATION_TIME.getName() );

    private static final String APPLIES_TO_OBJECT_CLASS = "person";


    private boolean memberAttributeSearch = false;

    
    //Should this be added to SchemaConstants?
    public static final String MEMBER_OF = "memberOf";
    public static final String MEMBER_OF_OID = "2.5.4.31.1";
    
    /**
     * 
     * Creates a new instance of MemberOfInterceptor.
     *
     * @param name This interceptor's getName()
     */
    public MemberOfInterceptor()
    {
        super( InterceptorEnum.MEMBEROF_INTERCEPTOR );
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public Entry lookup( LookupOperationContext lookupContext ) throws LdapException
    {
        Entry entry = next( lookupContext );
        conditionallyAddMemberOf( entry );

        return entry;
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public EntryFilteringCursor search( SearchOperationContext searchContext ) throws LdapException
    {
        EntryFilteringCursor cursor = next( searchContext );
        cursor.addEntryFilter( new MemberOfSearchFilter() );

        return cursor;
    }

    private void conditionallyAddMemberOf( Entry entry ) throws LdapException
    {
        if ( applies( entry ) )
        {
            addMemberOf( entry );
        }
    }

    private boolean applies( Entry entry )
    {
        if ( entry.hasObjectClass( APPLIES_TO_OBJECT_CLASS ) )
        {
            return true;
        }

        return false;
    }


    private void addMemberOf( Entry entry )
        throws LdapInvalidAttributeValueException, LdapInvalidDnException, LdapException, LdapOtherException
    {
        CoreSession adminSession = directoryService.getAdminSession();
        AttributeType member = directoryService.getAtProvider().getUniqueMember();
        if ( memberAttributeSearch ) 
        {
            member = directoryService.getAtProvider().getMember();
        }
        
        Value dnValue = new Value( member, entry.getDn().getNormName() );
        PartitionNexus nexus = directoryService.getPartitionNexus();
        ExprNode filter = new EqualityNode<String>( member, dnValue );

        Dn dnSearchBase = Dn.ROOT_DSE;

        SearchOperationContext searchOperationContext = new SearchOperationContext( adminSession, dnSearchBase,
            SearchScope.SUBTREE, filter, "1.1" );
        Partition partition = nexus.getPartition( dnSearchBase );
        searchOperationContext.setAliasDerefMode( AliasDerefMode.NEVER_DEREF_ALIASES );
        searchOperationContext.setPartition( partition );

        //Is this appropriate how to instantiate 'virtual' attribute types?:
        AttributeType atMemberOf = new AttributeType( MEMBER_OF_OID );
        atMemberOf.setNames( MEMBER_OF );
        atMemberOf.setSyntax( new VirtualSyntax() );
        
        try ( PartitionTxn partitionTxn = partition.beginReadTransaction() )
        {
            searchOperationContext.setTransaction( partitionTxn );
            EntryFilteringCursor results = nexus.search( searchOperationContext );

            try
            {
                while ( results.next() )
                {
                    Entry memberEntry = results.get();
                    entry.add( atMemberOf, memberEntry.getDn().toString() );
                }

                results.close();
            }
            catch ( Exception e )
            {
                throw new LdapOperationException( e.getMessage(), e );
            }
        }
        catch ( Exception e )
        {
            throw new LdapOtherException( e.getMessage(), e );
        }
    }


    public void setMemberAttributeSearch( boolean memberAttributeSearch )
    {
        this.memberAttributeSearch = memberAttributeSearch;
    }

    private class MemberOfSearchFilter implements EntryFilter
    {

        /**
         * {@inheritDoc}
         */
        @Override
        public boolean accept( SearchOperationContext operation, Entry entry ) throws LdapException
        {
            conditionallyAddMemberOf( entry );
            return true;
        }


        /**
         * {@inheritDoc}
         */
        @Override
        public String toString( String tabs )
        {
            return tabs + "MemberOfSearchFilter";
        }

    }
    
    private class VirtualSyntax extends LdapSyntax
    {
        VirtualSyntax()
        {
            super( MEMBER_OF_OID );
            addName( "memberOf" );
            isObsolete = false;
            isHumanReadable = true;
            syntaxChecker = DirectoryStringSyntaxChecker.builder().build();
        }
    }

}
