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
package org.apache.directory.server.kerberos.shared.messages.value;


import java.util.Arrays;

import org.apache.directory.server.kerberos.shared.crypto.checksum.ChecksumType;


public class Checksum
{
    private ChecksumType checksumType;
    private byte[] checksum;


    public Checksum(ChecksumType checksumType, byte[] checksum)
    {
        this.checksumType = checksumType;
        this.checksum = checksum;
    }


    public boolean equals( Object o )
    {
        if ( this == o )
        {
            return true;
        }

        if ( !( o instanceof Checksum ) )
        {
            return false;
        }

        Checksum that = ( Checksum ) o;

        return ( this.checksumType == that.checksumType ) && ( Arrays.equals( this.checksum, that.checksum ) );
    }


    public byte[] getChecksumValue()
    {
        return checksum;
    }


    public ChecksumType getChecksumType()
    {
        return checksumType;
    }
}
