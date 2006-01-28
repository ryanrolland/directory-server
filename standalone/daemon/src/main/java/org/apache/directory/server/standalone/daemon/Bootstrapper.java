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
package org.apache.directory.server.standalone.daemon;


import java.io.FileInputStream;
import java.lang.reflect.Method;
import java.net.URL;
import java.net.URLClassLoader;
import java.util.Properties;

import org.slf4j.LoggerFactory;
import org.slf4j.Logger;


/**
 * The main bootstrapper used when invoked as an application.
 * 
 * @author <a href="mailto:dev@directory.apache.org">Apache Directory Project</a>
 * @version $Rev$
 */
public class Bootstrapper
{
    private static final Logger log = LoggerFactory.getLogger( Bootstrapper.class );
    private static final String[] EMPTY_STRARRY = new String[0];
    private static final String START_CLASS_PROP = "bootstrap.start.class";
    private static final String STOP_CLASS_PROP = "bootstrap.stop.class";

    protected static Bootstrapper instance;
    
    private InstallationLayout install;
    private ClassLoader appLoader;
    private ClassLoader parentLoader;
    private String startClassName;
    private String stopClassName;
    private Class startObjectClass;
    private Class stopObjectClass;
    private Object startObject;
    private Object stopObject;

    
    public void setInstallationLayout( String installationBase )
    {
        log.debug( "Setting layout in Bootstrapper using base: " + installationBase );
        install = new InstallationLayout( installationBase );
        
        try
        {
            install.verifyInstallation();
        }
        catch( Throwable t )
        {
            log.error( "Installation verification failure!", t );
        }
        
        try
        {
            Properties props = new Properties();
            props.load( new FileInputStream( install.getBootstrapperConfigurationFile() ) );
            startClassName = props.getProperty( START_CLASS_PROP );
            stopClassName = props.getProperty( STOP_CLASS_PROP );
        }
        catch ( Exception e )
        {
            log.error( "Failed while loading: " + install.getBootstrapperConfigurationFile(), e );
            System.exit( ExitCodes.PROPLOAD );
        }
    }
    
    
    public void setParentLoader( ClassLoader parentLoader )
    {
        this.parentLoader = parentLoader;
        URL[] jars = install.getAllJars();
        this.appLoader = new URLClassLoader( jars, parentLoader );
        
        if ( log.isDebugEnabled() )
        {
            StringBuffer buf = new StringBuffer();
            buf.append( "urls in app loader: \n" );
            for ( int ii = 0; ii < jars.length; ii++ )
            {
                buf.append( "\t" ).append( jars[ii] ).append( "\n" );
            }
            log.debug( buf.toString() );
        }
    }


    public void callInit()
    {
        Method op = null;
        
        Thread.currentThread().setContextClassLoader( appLoader );
        try
        {
            startObjectClass = appLoader.loadClass( startClassName );
        }
        catch ( ClassNotFoundException e )
        {
            log.error( "Could not find " + startClassName, e );
            System.exit( ExitCodes.CLASS_LOOKUP );
        }
        
        try
        {
            startObject = startObjectClass.newInstance();
        }
        catch ( Exception e )
        {
            log.error( "Could not instantiate " + startClassName, e );
            System.exit( ExitCodes.INSTANTIATION );
        }
        
        try
        {
            op = startObjectClass.getMethod( "init", new Class[] { InstallationLayout.class } );
        }
        catch ( Exception e )
        {
            log.error( "Could not find init(InstallationLayout) method for " + startClassName, e );
            System.exit( ExitCodes.METHOD_LOOKUP );
        }
        
        try
        {
            op.invoke( startObject, new Object[] { this.install } );
        }
        catch ( Exception e )
        {
            log.error( "Failed on " + startClassName + ".init(InstallationLayout)", e );
            System.exit( ExitCodes.INITIALIZATION );
        }
    }

    
    public void callStart()
    {
        Method op = null;
        
        try
        {
            op = startObjectClass.getMethod( "start", null );
        }
        catch ( Exception e )
        {
            log.error( "Could not find start() method for " + startObjectClass.getName(), e );
            System.exit( ExitCodes.METHOD_LOOKUP );
        }
        
        try
        {
            op.invoke( startObject, null );
        }
        catch ( Exception e )
        {
            log.error( "Failed on " + startObjectClass.getName() + ".start()", e );
            System.exit( ExitCodes.START );
        }
    }
    

    public void callStop()
    {
        Class clazz = null;
        Method op = null;
        
        if ( startClassName.equals( stopClassName ) && startObject != null )
        {
            clazz = startObjectClass;
            stopObject = startObject;
        }
        else
        {
            try
            {
                clazz = appLoader.loadClass( stopClassName );
            }
            catch ( ClassNotFoundException e )
            {
                log.error( "Could not find " + stopClassName, e );
                System.exit( ExitCodes.CLASS_LOOKUP );
            }
            
            try
            {
                stopObject = clazz.newInstance();
            }
            catch ( Exception e )
            {
                log.error( "Could not instantiate " + stopClassName, e );
                System.exit( ExitCodes.INSTANTIATION );
            }
        }
        
        try
        {
            op = clazz.getMethod( "stop", new Class[] { EMPTY_STRARRY.getClass() } );
        }
        catch ( Exception e )
        {
            log.error( "Could not find stop() method for " + stopClassName, e );
            System.exit( ExitCodes.METHOD_LOOKUP );
        }
        
        try
        {
            op.invoke( stopObject, new Object[] { EMPTY_STRARRY } );
        }
        catch ( Exception e )
        {
            log.error( "Failed on " + stopClassName + ".stop()", e );
            System.exit( ExitCodes.STOP );
        }
    }

    
    public void callDestroy()
    {
        Method op = null;
        try
        {
            op = stopObject.getClass().getMethod( "destroy", null );
        }
        catch ( Exception e )
        {
            log.error( "Could not find destroy() method for " + stopClassName, e );
            System.exit( ExitCodes.METHOD_LOOKUP );
        }
        
        try
        {
            op.invoke( stopObject, null );
        }
        catch ( Exception e )
        {
            log.error( "Failed on " + stopClassName + ".destroy()", e );
            System.exit( ExitCodes.STOP );
        }
    }

    
    // -----------------------------------------------------------------------
    
    
    public void init( String[] args )
    {
        if ( log.isDebugEnabled() )
        {
            StringBuffer buf = new StringBuffer();
            buf.append( "init(String[]) called with args: \n" );
            for ( int ii = 0; ii < args.length; ii++ )
            {
                buf.append( "\t" ).append( args[ii] ).append( "\n" );
            }
            log.debug( buf.toString() );
        }

        if ( install == null )
        {
            log.debug( "install was null: initializing it using first argument" );
            setInstallationLayout( args[0] );
            log.debug( "install initialized" );
        }
        else
        {
            log.debug( "install was not null" );
        }

        if ( parentLoader == null )
        {
            log.info( "Trying to get handle on system classloader as the parent" );
            setParentLoader( Thread.currentThread().getContextClassLoader() );
            log.info( "parentLoader = " + parentLoader );
        }
        
        callInit();

        // This is only needed for procrun but does not harm jsvc or runs 
        // Leads me to think that we need to differentiate somehow between
        // different daemon frameworks.  We can do this via command line args,
        // system properties or by making them call different methods to start
        // the process.  However not every framework may support calling 
        // different methods which may also be somewhat error prone.
        
        while( true )
        {
            try
            {
                Thread.sleep( 2000 );
            }
            catch ( InterruptedException e )
            {
                e.printStackTrace();
            }
        }
    }
    
    
    public void start()
    {
        log.debug( "start() called" );
        Thread.currentThread().setContextClassLoader( parentLoader );
        callStart();
    }


    public void start( String[] args )
    {
        log.debug( "start(String[]) called" );
        Thread.currentThread().setContextClassLoader( this.parentLoader );
        
        if ( install == null && args.length > 0 )
        {
            setInstallationLayout( args[0] );
            setParentLoader( Thread.currentThread().getContextClassLoader() );
        }
    }

    
    public void stop() throws Exception
    {
        log.debug( "stop() called" );
        callStop();
    }


    public void destroy()
    {
        log.debug( "destroy() called" );
        callDestroy();
    }
}