/*
 *   Copyright 2004 The Apache Software Foundation
 *
 *   Licensed under the Apache License, Version 2.0 (the "License");
 *   you may not use this file except in compliance with the License.
 *   You may obtain a copy of the License at
 *
 *       http://www.apache.org/licenses/LICENSE-2.0
 *
 *   Unless required by applicable law or agreed to in writing, software
 *   distributed under the License is distributed on an "AS IS" BASIS,
 *   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *   See the License for the specific language governing permissions and
 *   limitations under the License.
 *
 */
package org.apache.ldap.server.schema;


import java.util.HashMap;
import java.util.Map;
import javax.naming.NamingException;

import org.apache.ldap.common.schema.Normalizer;
import org.apache.ldap.server.SystemPartition;
import org.apache.ldap.server.schema.bootstrap.BootstrapNormalizerRegistry;


/**
 * A simple POJO implementation of the NormalizerRegistry service interface.
 *
 * @author <a href="mailto:directory-dev@incubator.apache.org">Apache Directory Project</a>
 * @version $Rev$
 */
public class GlobalNormalizerRegistry implements NormalizerRegistry
{
    /** the normalizers in this registry */
    private final Map normalizers;
    /** maps an OID to a schema name*/
    private final Map oidToSchema;
    /** the monitor for delivering callback events */
    private NormalizerRegistryMonitor monitor;
    /** the underlying bootstrap registry to delegate on misses to */
    private BootstrapNormalizerRegistry bootstrap;
    /** the system partition where we keep attributeType updates */
    private SystemPartition systemPartition;


    // ------------------------------------------------------------------------
    // C O N S T R U C T O R S
    // ------------------------------------------------------------------------


    /**
     * Creates a default NormalizerRegistry by initializing the map and the
     * montior.
     */
    public GlobalNormalizerRegistry( SystemPartition systemPartition,
            BootstrapNormalizerRegistry bootstrap )
    {
        this.oidToSchema = new HashMap();
        this.normalizers = new HashMap();
        this.monitor = new NormalizerRegistryMonitorAdapter();

        this.bootstrap = bootstrap;
        if ( this.bootstrap == null )
        {
            throw new NullPointerException( "the bootstrap registry cannot be null" ) ;
        }

        this.systemPartition = systemPartition;
        if ( this.systemPartition == null )
        {
            throw new NullPointerException( "the system partition cannot be null" ) ;
        }
    }


    /**
     * Sets the monitor used by this registry.
     *
     * @param monitor the monitor to set for registry event callbacks
     */
    public void setMonitor( NormalizerRegistryMonitor monitor )
    {
        this.monitor = monitor;
    }


    // ------------------------------------------------------------------------
    // Service Methods
    // ------------------------------------------------------------------------


    public void register( String schema, String oid, Normalizer normalizer )
            throws NamingException
    {
        if ( normalizers.containsKey( oid ) || bootstrap.hasNormalizer( oid ) )
        {
            NamingException e = new NamingException( "Normalizer with OID "
                + oid + " already registered!" );
            monitor.registerFailed( oid, normalizer, e );
            throw e;
        }

        oidToSchema.put( oid, schema );
        normalizers.put( oid, normalizer );
        monitor.registered( oid, normalizer );
    }


    public Normalizer lookup( String oid ) throws NamingException
    {
        Normalizer c;
        NamingException e;

        if ( normalizers.containsKey( oid ) )
        {
            c = ( Normalizer ) normalizers.get( oid );
            monitor.lookedUp( oid, c );
            return c;
        }

        if ( bootstrap.hasNormalizer( oid ) )
        {
            c = bootstrap.lookup( oid );
            monitor.lookedUp( oid, c );
            return c;
        }

        e = new NamingException( "Normalizer not found for OID: " + oid );
        monitor.lookupFailed( oid, e );
        throw e;
    }


    public boolean hasNormalizer( String oid )
    {
        return normalizers.containsKey( oid ) || bootstrap.hasNormalizer( oid );
    }


    public String getSchemaName( String oid ) throws NamingException
    {
        if ( ! Character.isDigit( oid.charAt( 0 ) ) )
        {
            throw new NamingException( "OID " + oid + " is not a numeric OID" );
        }
        
        if ( oidToSchema.containsKey( oid ) )
        {
            return ( String ) oidToSchema.get( oid );
        }

        if ( bootstrap.hasNormalizer( oid ) )
        {
            return bootstrap.getSchemaName( oid );
        }

        throw new NamingException( "OID " + oid + " not found in oid to " +
            "schema name map!" );
    }
}
