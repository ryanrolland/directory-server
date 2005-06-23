/*
 *   @(#) $Id$
 *
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
package org.apache.ldap.server.configuration;

import java.util.ArrayList;
import java.util.Collection;
import java.util.HashSet;
import java.util.Iterator;
import java.util.List;
import java.util.Set;

import javax.naming.directory.Attributes;

/**
 * A utility class that provides common functionality while validating configuration.
 * 
 * @author <a href="mailto:dev@directory.apache.org">Apache Directory Project</a>
 * @version $Rev$, $Date$
 */
class ConfigurationUtil
{
    /**
     * Checks all elements of the specified set is of the specified type,
     * and returns cloned set.
     * 
     * @throws ConfigurationException if the specified set has an element of wrong type
     */
    static Set getTypeSafeSet( Set set, Class type )
    {
        Set newSet = new HashSet();
        getTypeSafeCollection( set, type, newSet );
        return newSet;
    }

    /**
     * Checks all elements of the specified list is of the specified type,
     * and returns cloned list.
     * 
     * @throws ConfigurationException if the specified set has an element of wrong type
     */
    static List getTypeSafeList( List list, Class type )
    {
        List newList = new ArrayList();
        getTypeSafeCollection( list, type, newList );
        return newList;
    }

    private static void getTypeSafeCollection( Collection collection, Class type, Collection newCollection )
    {
        Iterator i = collection.iterator();
        while( i.hasNext() )
        {
            Object e = i.next();
            if( !type.isAssignableFrom( e.getClass() ) )
            {
                throw new ConfigurationException(
                        "Invalid element type: " + e.getClass() +
                        " (expected " + type );
            }
            newCollection.add( e );
        }
    }
    
    /**
     * Returns the clone of the specified set.
     */
    static Set getClonedSet( Set set )
    {
        Set newSet = new HashSet();
        newSet.addAll( set );
        return newSet;
    }
    
    /**
     * Returns the clone of the specified list.
     */
    static List getClonedList( List list )
    {
        List newList = new ArrayList();
        newList.addAll( list );
        return newList;
    }
    
    /**
     * Returns the deep clone of the specified {@link Attributes} set.
     */
    static Set getClonedAttributesSet( Set set )
    {
        Set newSet = new HashSet();
        Iterator i = set.iterator();
        while( i.hasNext() )
        {
            newSet.add( ( ( Attributes ) i.next() ).clone() );
        }
        return newSet;
    }

    /**
     * Throws a {@link ConfigurationException} if the specified port number
     * is out of range.
     */
    static void validatePortNumber( int port )
    {
        if( port < 0 || port > 65535 )
        {
            throw new ConfigurationException( "Invalid port number: " + port );
        }
    }
    
    private ConfigurationUtil()
    {
    }
}
