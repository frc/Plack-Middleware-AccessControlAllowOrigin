package Plack::Middleware::AccessControlAllowOrigin;
use strict;
use warnings;
our $VERSION = '0.02';
use parent 'Plack::Middleware';

use Plack::Util;
use Plack::Util::Accessor 'origin';
use Plack::Util::Accessor 'allow_credentials';
use Plack::Util::Accessor 'origin_whitelist';

sub call {
    my $self = shift;
    my $env = shift;
    my $request_origin = $env->{'HTTP_ORIGIN'};

    my $res  = $self->app->(@_);
    $self->response_cb($res, sub {
        my $res = shift;
        my $origin;

        if ($self->origin_whitelist()) {
            if ($request_origin =~ $self->origin_whitelist()) {
                # Request origin is whitelisted, accept.
                $origin = $request_origin;
            } else {
                # Request origin is not whitelisted, don't accept.
                # $origin stays undef, no headers set
            }
        } elsif ($self->allow_credentials and $self->origin eq '*') {
            die('You must use origin_whitelist if you allow_credentials, wildcard origin "*" is not supported in CORS.');
        } else {
            # Allow_credentials is false or origin wildcard is not used, use basic origin setting
            $origin = $self->origin;
        }

        if ($origin) {
            Plack::Util::header_set($res->[1],
                'Access-Control-Allow-Origin' => $origin
            );
            if ($self->allow_credentials) {
                Plack::Util::header_set($res->[1],
                    'Access-Control-Allow-Credentials' => 'true'
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

=item origin

Specify the value of C<Access-Control-Allow-Origin> header.

=item allow_credentials

Specify if sending credentials is allowed. Defaults to false.

=back

=head1 AUTHOR

punytan E<lt>punytan@gmail.comE<gt>

=head1 SEE ALSO

=head1 LICENSE

This library is free software; you can redistribute it and/or modify
it under the same terms as Perl itself.

=cut
