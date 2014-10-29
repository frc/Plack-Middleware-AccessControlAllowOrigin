package Plack::Middleware::AccessControlAllowOrigin;
use strict;
use warnings;
our $VERSION = '0.02';
use parent 'Plack::Middleware';

use Plack::Util;
use Plack::Util::Accessor 'allow_origin';
use Plack::Util::Accessor 'allow_credentials';
use Plack::Util::Accessor 'origin_whitelist';
use Plack::Util::Accessor 'allow_methods';
use Plack::Util::Accessor 'origin_fallback';

sub call {
    my $self = shift;
    my $env = shift;
    my $request_origin = $env->{'HTTP_ORIGIN'};


    my $res  = $self->app->(@_);
    $self->response_cb($res, sub {
        my $res = shift;
        my $allow_origin;

        if ($self->origin_whitelist()) {
            if ($request_origin =~ $self->origin_whitelist()) {
                # Request origin is whitelisted, accept.
                $allow_origin = $request_origin;
            } else {
                # Request origin is not whitelisted, don't accept.
                # $allow_origin stays undef, no headers set
            }
        } elsif ($self->allow_credentials and $self->allow_origin eq '*') {
            die('You must use origin_whitelist if you allow_credentials, wildcard allow_origin "*" is not supported in CORS.');
        } else {
            # Allow_credentials is false or origin wildcard is not used, use basic origin setting
            $allow_origin = $self->allow_origin;
        }

        if ($allow_origin) {
            Plack::Util::header_set($res->[1],
                'Access-Control-Allow-Origin' => $allow_origin
            );
            if ($self->allow_credentials) {
                Plack::Util::header_set($res->[1],
                    'Access-Control-Allow-Credentials' => 'true'
                );
            }
        }

        if ($self->allow_methods) {
            if ($self->allow_credentials and $self->allow_methods eq '*') {
                die('Wildcard "*" for methods is not supported in CORS when allow_credentials is true');
            } else {
                Plack::Util::header_set($res->[1],
                    'Access-Control-Allow-Methods' => $self->allow_methods
                );
            }
        }

    });
}

1;
__END__

=head1 NAME

Plack::Middleware::AccessControlAllowOrigin - Add Access-Control-Allow-Origin header

=head1 SYNOPSIS

    builder {
        enable 'Plack::Middleware::AccessControlAllowOrigin', origin => '*';
        $app;
    };

=head1 DESCRIPTION

Plack::Middleware::AccessControlAllowOrigin adds C<Access-Control-Allow-Origin> header.

=head1 CONFIGURATION

=over 4

=item allow_origin

Specify the value of C<Access-Control-Allow-Origin> header.

=item allow_credentials

Specify if sending credentials is allowed. Defaults to false.

=back

=head1 AUTHORS

punytan E<lt>punytan@gmail.comE<gt>, Oskari Okko Ojala E<lt>okko@perl.org<gt>

=head1 SEE ALSO

https://developer.mozilla.org/en-US/docs/Web/HTTP/Access_control_CORS

=head1 LICENSE

This library is free software; you can redistribute it and/or modify
it under the same terms as Perl itself.

=cut
