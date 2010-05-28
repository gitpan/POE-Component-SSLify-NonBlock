# Declare our package
package POE::Component::SSLify::NonBlock;
use strict;
use warnings;
use POE::Component::SSLify::NonBlock::ServerHandle;
use Exporter;

use vars qw( $VERSION @ISA );
$VERSION = '0.32';

@ISA = qw(Exporter);
use vars qw( @EXPORT_OK );
@EXPORT_OK = qw( Server_SSLify_NonBlock SSLify_Options_NonBlock_ClientCert Server_SSLify_NonBlock_ClientCertVerifyAgainstCRL Server_SSLify_NonBlock_SSLDone
                  Server_SSLify_NonBlock_GetClientCertificateIDs  Server_SSLify_NonBlock_ClientCertificateExists  Server_SSLify_NonBlock_ClientCertIsValid );

use Symbol qw( gensym );

sub Server_SSLify_NonBlock_SSLDone {
   my $socket = shift;
   my $acceptstateclient = tied( *$socket )->_get_self()->{acceptstate}
      if exists(tied( *$socket )->_get_self()->{acceptstate});
   return 1 if ($acceptstateclient > 2);
   return 0;
}

sub SSLify_Options_NonBlock_ClientCert {
   my $ctx = shift;
   my $cacrt = shift;
   my $count = shift || 5;
   # CA File einlesen, wenn wir eins haben
   Net::SSLeay::CTX_load_verify_locations($ctx, $cacrt, '') || die $!;

   # Setzen welche Clientzertifkate wir moegen...
   Net::SSLeay::CTX_set_client_CA_list($ctx, Net::SSLeay::load_client_CA_file($cacrt));

   # Wir ueberpruefen auch signierte Zertifikate....
   Net::SSLeay::CTX_set_verify_depth($ctx, $count);
}

# Okay, the main routine here!
sub Server_SSLify_NonBlock {
   # Get the socket!
   my $ctx = shift;
   my $socket = shift;
   my $params = shift;

   # Validation...
   if ( ! defined $socket ) {
      die "Did not get a defined socket";
   }

   # If we don't have a ctx ready, we can't do anything...
   if ( ! defined $ctx ) {
      die 'Please do SSLify_Options() first';
   }

   $socket->blocking( 0 );

   # Now, we create the new socket and bind it to our subclass of Net::SSLeay::Handle
   my $newsock = gensym();
   tie( *$newsock, 'POE::Component::SSLify::NonBlock::ServerHandle', $socket, $ctx, $params ) or die "Unable to tie to our subclass: $!";

   # All done!
   return $newsock;
}

sub Server_SSLify_NonBlock_ClientCertificateExists {
   my $socket = shift;
   my $infos = tied( *$socket )->_get_self()->{infos};
   return ((ref($infos) eq "ARRAY") && ($infos->[1]));
}

sub Server_SSLify_NonBlock_ClientCertIsValid {
   my $socket = shift;
   my $infos = tied( *$socket )->_get_self()->{infos};
   return Server_SSLify_NonBlock_ClientCertificateExists($socket) ? (($infos->[0] eq "1") && (ref($infos->[2]) eq "ARRAY") && scalar(@{$infos->[2]})) ? 1 : 0 : 0;
}

sub Server_SSLify_NonBlock_GetClientCertificateIDs {
   my $socket = shift;
   my $infos = tied( *$socket )->_get_self()->{infos};
   return Server_SSLify_NonBlock_ClientCertificateExists($socket) ? @{$infos->[2]} : undef;
}

sub Server_SSLify_NonBlock_ClientCertVerifyAgainstCRL {
   my $socket = shift;
   my $crlfilename = shift;
   my $infos = tied( *$socket )->_get_self()->{infos};
   my @certids = Server_SSLify_NonBlock_GetClientCertificateIDs($socket);
   if (scalar(@certids)) {
      my $found = 0;
      my $badcrls = 0;
      my $jump = 0;
      print("----- SSL Infos BEGIN ---------------"."\n")
         if (tied( *$socket )->_get_self()->{debug});
      foreach (@{$infos->[2]}) {
         my $crlstatus = Net::SSLeay::verify_serial_against_crl_file($crlfilename, $_->[2]);
         $badcrls++ if $crlstatus;
         $crlstatus = $crlstatus ? "INVALID (".($crlstatus !~ m,^CRL:, ? hexdump($crlstatus) : $crlstatus).")" : "VALID";
         my $t = ("  " x $jump++);
         if (ref($_) eq "ARRAY") {
            if (tied( *$socket )->_get_self()->{debug}){
               print(" ".$t."  |---[ Subcertificate ]---\n") if $t;
               print(" ".$t."  | Subject Name: ".$_->[0]."\n");
               print(" ".$t."  | Issuer Name : ".$_->[1]."\n");
               print(" ".$t."  | Serial      : ".hexdump($_->[2])."\n");
               print(" ".$t."  | CRL Status  : ".$crlstatus."\n");
            }
         } else {
            print(" NOCERTINFOS!"."\n")
               if (tied( *$socket )->_get_self()->{debug});
            return 0;
         }
      }
      print("----- SSL Infos END -----------------"."\n")
         if (tied( *$socket )->_get_self()->{debug});
      return 1 unless $badcrls;
   }
   return 0;
}

sub hexdump { join ':', map { sprintf "%02X", $_ } unpack "C*", $_[0]; }

__END__

=head1 NAME

POE::Component::SSLify::NonBlock - Nonblocking SSL for POE with client certificate verification.

=head1 SYNOPSIS

=head2 Server-side usage

   # Import the modules
   use POE::Component::SSLify qw( SSLify_Options SSLify_GetCTX );
   use POE::Component::SSLify::NonBlock qw( Server_SSLify_NonBlock );

   # Set the key + certificate file, only one time needed.
   eval { SSLify_Options( 'server.key', 'server.crt' ) };
   if ( $@ ) {
      # Unable to load key or certificate file...
   }

   # Create a normal SocketFactory wheel or something
   my $factory = POE::Wheel::SocketFactory->new( ... );

   # Converts the socket into a SSL socket POE can communicate with, every time on new socket needed.
   eval { $socket = Server_SSLify_NonBlock( SSLify_GetCTX(), $socket, { } ) };
   if ( $@ ) {
      # Unable to SSLify it...
   }

   # Now, hand it off to ReadWrite
   my $rw = POE::Wheel::ReadWrite->new(
      Handle   =>   $socket,
      ...
   );

=head1 ABSTRACT

Nonblocking SSL for POE with client certificate verification.

=head1 DESCRIPTION

This component represents a common way of using ssl on a server, which
needs to ensure that not one client can block the whole server. Further
it allows to verificate client certificates.

=head2 Non-Blocking needed, espacielly on client certification verification

SSL is a protocol which interacts with the client during the handshake multiple times. If
the socket is blocking, as on pure POE::Component::SSLify, one client can block the whole
server.
Especially if you want to do client certificate verification, the user has the
abilty to choose a client certificate. In this situation the ssl handshake is waiting,
and in blocked mode the whole server also stops responding.

=head2 Client certificate verification

You have three opportunities to do client certificate verification:

  Easiest way: 
    Verify the certificate and let OpenSSL reject the connection during ssl handshake if there is no certificate or if it is unstrusted.

  Advanced way:
    Verify the certificate and poe handler determines if there is no certificate or if it is unstrusted.

  Complicated way:
    Verify the certificate and poe handler determines if there is no certificate, if it is unstrusted or if it is blocked by a CRL.

=head3 Easiest way: Client certificat rejection in ssl handshake

Generaly you can use the "Server-side usage" example above, but you have to enable the client certification
feature with the "clientcertrequest" paramter. The Server_SSLify_NonBlock function allows a hash for parameters:

   use POE::Component::SSLify qw( SSLify_Options SSLify_GetCTX );
   use POE::Component::SSLify::NonBlock qw( Server_SSLify_NonBlock SSLify_Options_NonBlock_ClientCert );
   
   eval { SSLify_Options( 'server.key', 'server.crt' ) };
   if ( $@ ) {
      # Unable to load key or certificate file...
   }
   
   eval { SSLify_Options_NonBlock_ClientCert(SSLify_GetCTX(), 'ca.crt')) };
   if ( $@ ) {
      # Unable to load certificate file...
   }
   
   ...
   
   eval { $heap->{socket} = Server_SSLify_NonBlock(SSLify_GetCTX(), $heap->{socket}, {
      clientcertrequest => 1
   } ) };
   if ( $@ ) {
      print "SSL Failed: ".$@."\n";
      delete $heap->{wheel_client};
   }

Now the server sends during SSL handshake the request for a client certificate. By default,
POE::Component::SSLify::NonBlock aborts the connection if "clientcertrequest" is set and there
is no client certificat or the certificate is not trusted.

=head3 Advanced way: Client certificat reject in POE Handler

   use POE::Component::SSLify qw( SSLify_Options SSLify_GetCTX );
   use POE::Component::SSLify::NonBlock qw( Server_SSLify_NonBlock SSLify_Options_NonBlock_ClientCert Server_SSLify_NonBlock_SSLDone );
   
   eval { SSLify_Options( 'server.key', 'server.crt' ) };
   if ( $@ ) {
      # Unable to load key or certificate file...
   }
   
   eval { SSLify_Options_NonBlock_ClientCert(SSLify_GetCTX(), 'ca.crt')) };
   if ( $@ ) {
      # Unable to load certificate file...
   }
   
   ...

   client_accept => sub {
      ...
      eval { $heap->{socket} = Server_SSLify_NonBlock( SSLify_GetCTX(), $socket, {
         clientcertrequest => 1,
         noblockbadclientcert => 1
      } ) };
      if ( $@ ) {
         print "SSL Failed: ".$@."\n";
         delete $heap->{wheel_client};
      }
      $heap->{wheel_client} = POE::Wheel::ReadWrite->new(
         Handle     => $heap->{socket},
         Driver     => POE::Driver::SysRW->new,
         Filter     => POE::Filter::Stream->new,
         InputEvent => 'client_input',
         ...
      }
   },
   client_input => sub {
      my ( $heap, $kernel, $input ) = @_[ HEAP, KERNEL, ARG0 ];
      my $canwrite = exists $heap->{wheel_client} &&
                       (ref($heap->{wheel_client}) eq "POE::Wheel::ReadWrite");
      return unless Server_SSLify_NonBlock_SSLDone($heap->{socket});
      if (!(Server_SSLify_NonBlock_ClientCertificateExists($heap->{socket}))) {
         exists $heap->{wheel_client} &&
           (ref($heap->{wheel_client}) eq "POE::Wheel::ReadWrite") &&
                $heap->{wheel_client}->put("Content-type: text/html\r\n\r\nNoClientCertExists");
         $kernel->yield("disconnect");
         return;
      } elsif(!(Server_SSLify_NonBlock_ClientCertIsValid($heap->{socket}))) {
         exists $heap->{wheel_client} &&
           (ref($heap->{wheel_client}) eq "POE::Wheel::ReadWrite") &&
                $heap->{wheel_client}->put("Content-type: text/html\r\n\r\nClientCertInvalid");
         $kernel->yield("disconnect");
         return;
      }
      ...
   },
   disconnect => sub { $_[KERNEL]->delay(close_delayed => 1) unless ($_[HEAP]->{disconnecting}++); },
   close_delayed => sub {
      my ($kernel, $heap) = @_[KERNEL, HEAP];
      delete $heap->{wheel_client};
   },
   ...

=head3 Complicated way: Client certificat reject in POE Handler with CRL support

WARNING: For this to work you have to patch into Net::SSLeay the lines in the file
net-ssleay-patch in the base path of the tar.gz of the packet, and then recompile and
reinstall the Net::SSLeay package.

Here an solution with SSL/TLS on the fly and client authentication, initiated via "STARTTLS".
For example if you want to do IMAPS, POPS or FTPS.

   use POE::Component::SSLify qw( SSLify_Options SSLify_GetCTX );
   use POE::Component::SSLify::NonBlock qw( Server_SSLify_NonBlock SSLify_Options_NonBlock_ClientCert Server_SSLify_NonBlock_ClientCertVerifyAgainstCRL Server_SSLify_NonBlock_SSLDone );
   
   eval { SSLify_Options( 'server.key', 'server.crt' ) };
   if ( $@ ) {
      # Unable to load key or certificate file...
   }
   
   eval { SSLify_Options_NonBlock_ClientCert(SSLify_GetCTX(), 'ca.crt')) };
   if ( $@ ) {
      # Unable to load certificate file...
   }
   
   ...

   client_accept => sub {
      ...
      $heap->{wheel_client} = POE::Wheel::ReadWrite->new(
         Handle     => $heap->{socket},
         Driver     => POE::Driver::SysRW->new,
         Filter     => POE::Filter::Stream->new,
         InputEvent => 'client_input',
         ...
      }
      $heap->{mode} = 'plain';
   },
   client_input => sub {
      my ( $heap, $kernel, $input ) = @_[ HEAP, KERNEL, ARG0 ];
      my $canwrite = exists $heap->{wheel_client} &&
                       (ref($heap->{wheel_client}) eq "POE::Wheel::ReadWrite");
      if ($heap->{mode} eq "plain") {
         if ($input ~= /STARTTLS/) {
            $heap->{wheel_client}->put("Do now SSL Handshake.\n") if $canwrite;
            eval { $heap->{socket} = Server_SSLify_NonBlock( SSLify_GetCTX(), $socket, {
               clientcertrequest => 1,
               noblockbadclientcert => 1,
               getserial => 1
            } ) };
            if ( $@ ) {
               print "SSL Failed: ".$@."\n";
               delete $heap->{wheel_client};
            }
            $heap->{mode} = 'sslhandshake';
         } else {
            $heap->{wheel_client}->put("First start TLS SSL with the 'STARTTLS' command.\n") if $canwrite;
         }
      } elsif($heap->{mode} eq 'sslhandshake') {
         return unless Server_SSLify_NonBlock_SSLDone($heap->{socket});
         if (!(Server_SSLify_NonBlock_ClientCertificateExists($heap->{socket}))) {
            $heap->{wheel_client}->put("NoClientCertExists") if $canwrite;
            $kernel->yield("disconnect");
            return;
         } elsif(!(Server_SSLify_NonBlock_ClientCertIsValid($heap->{socket}))) {
            $heap->{wheel_client}->put("ClientCertInvalid") if $canwrite;
            $kernel->yield("disconnect");
            return;
         } elsif(!(Server_SSLify_NonBlock_ClientCertVerifyAgainstCRL($heap->{socket}, 'ca.crl'))) {
            $heap->{wheel_client}->put("CRL") if $canwrite;
            $kernel->yield("disconnect");
            return;
         }
         $heap->{mode} = 'crytped';
      }
      if ($heap->{mode} eq "cryped") {
         $heap->{wheel_client}->put("Yeah! You're authenticated!") if $canwrite;
         $kernel->yield("disconnect");
      }
   },
   disconnect => sub { $_[KERNEL]->delay(close_delayed => 1) unless ($_[HEAP]->{disconnecting}++); },
   close_delayed => sub {
      my ($kernel, $heap) = @_[KERNEL, HEAP];
      delete $heap->{wheel_client};
   },
   ...

=head1 FUNCTIONS

=head2 SSLify_Options_NonBlock_ClientCert($ctx, $cacrt)

Configures ssl ctx(context) to request from the client a
certificate for authentication, which is verificated against
the configured CA in the file $cacrt.

   SSLify_Options_NonBlock_ClientCert(SSLify_GetCTX(), 'ca.crt');

Note:

   SSLify_Options from POE::Component::SSLify must be first called !

=head2 Server_SSLify_NonBlock($ctx, $socket, %$options)

Similar to Server_SSLify from POE::Component::SSLify. It needs further the CTX of POE::Component::SSLify and a hash for special options:

   my $socket = shift;   # get the socket from somewhere
   $socket = Server_SSLify_NonBlock(SSLify_GetCTX(), $socket, { option1 => 1, option1 => 2,... });

Options are:

   clientcertrequest
      The client is requested for a client certificat during
      ssl handshake

   noblockbadclientcert
      If the client do not provide a client certificate, or the
      client certificate is untrusted, the connection will not
      be aborted. You can check for the errors via the functions
      Server_SSLify_NonBlock_ClientCertificateExists and
      Server_SSLify_NonBlock_ClientCertIsValid.

   debug
      Get debug messages during ssl handshake. Espacally usefull
      for Server_SSLify_NonBlock_ClientCertVerifyAgainstCRL.

   getserial
      Request the serial of the client certificate during
      ssl handshake.
      
      WARNING: You have to patch Net::SSLeay to provide the
               Net::SSLeay::X509_get_serialNumber function
               before you can set the getserial option! See the
               file net-ssleay-patch in the base path of the
               tar.gz of the packet.

Note:

   SSLify_Options from POE::Component::SSLify must be set first!

=head2 Server_SSLify_NonBlock_SSLDone

Checks if the SSL handshake has been completed.

   Server_SSLify_NonBlock_SSLDone($socket);

=head2 Server_SSLify_NonBlock_ClientCertificateExists($socket)

Verify if the client commited a valid client certificate.

  Server_SSLify_NonBlock_ClientCertificateExists($socket);

=head2 Server_SSLify_NonBlock_ClientCertIsValid($socket)

Verify if the client certifcate is trusted by a loaded CA (see SSLify_Options_NonBlock_ClientCert).

  Server_SSLify_NonBlock_ClientCertIsValid($socket);

=head2 Server_SSLify_NonBlock_ClientCertVerifyAgainstCRL($socket, $crlfile)

Opens a CRL file, and verify if the serial of the client certificate
is not contained in the CRL file. No file caching is done, each run opens
the file new.

Note: If your CRL File is missing, can not be opened or has no blocked
      certificate at all, every call will get blocked.

  Server_SSLify_NonBlock_ClientCertVerifyAgainstCRL($socket, 'ca.crl');
  
   WARNING: You have to patch Net::SSLeay to provide the
            Net::SSLeay::verify_serial_against_crl_file function
            before you can set the getserial option! See the
            file net-ssleay-patch in the base path of the tar.gz
            of the packet.


=head2 Futher functions...

You can use all functions from POE::Component::SSLify !

=head1 NOTES

=head2 Based on POE::Component::SSLify

This module is based on POE::Component::SSLify, so we have in POE::Component::SSLify::NonBlock the same issues as on POE::Component::SSLify.

=head1 EXPORT

Stuffs all of the above functions in @EXPORT_OK so you have to request them directly

=head1 BUGS

=head2 Server_SSLify_NonBlock_ClientCertVerifyAgainstCRL: certificate serials

Server_SSLify_NonBlock_ClientCertVerifyAgainstCRL also verifies against the serial 
of the CA ! Make sure that you never use the serial of the CA for client certificates!

=head2 Win32

I did not test POE::Component::SSLify::NonBlock on Win32 platforms at all!

=head1 SEE ALSO

L<POE::Component::SSLify>

L<Net::SSLeay>

=head1 AUTHOR

pRiVi E<lt>pRiVi@cpan.orgE<gt>

=head1 PROPS

This code is based on Apocalypse module POE::Component::SSLify, improved by client certification code and non-blocking sockets.

Copyright 2010 by Markus Mueller/Apocalypse/Rocco Caputo/Dariusz Jackowski.

=head1 COPYRIGHT AND LICENSE

Copyright 2010 by Markus Mueller

This library is free software; you can redistribute it and/or modify
it under the same terms as Perl itself.

=cut
