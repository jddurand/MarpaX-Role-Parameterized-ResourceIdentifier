use strict;
use warnings FATAL => 'all';

package MarpaX::Role::Parameterized::ResourceIdentifier::Role::ldap;
use MarpaX::Role::Parameterized::ResourceIdentifier::Setup;
use MarpaX::RFC::RFC3629;
use Carp qw/croak/;
use Encode qw/_utf8_off/;
use Scalar::Util qw/blessed/;

our $setup = MarpaX::Role::Parameterized::ResourceIdentifier::Setup->new;
our $RFC3986_gen_delims_characters   = qr'(?:[:/?#\[\]@])';
our $RFC3986_sub_delims_characters   = qr'(?:[!$&\'()*+,;=])';
our $RFC3986_reserved_characters     = qr/(?:$RFC3986_gen_delims_characters|$RFC3986_sub_delims_characters)/;
our $RFC3986_unreserved_characters   = qr/(?:[A-Za-z0-9-._~])/;
our $RFC3986_characters_no_to_encode = qr/(?:$RFC3986_reserved_characters|$RFC3986_unreserved_characters)/;

# ABSTRACT: Resource Identifier: ldap syntax semantics common overrides role

# VERSION

# AUTHORITY

use Moo::Role;

around default_port => sub { 389 };

#
# Arguments of every callback:
# my ($self, $field, $value, $lhs) = @_;
#
around build_percent_encoding_normalizer => sub {
  my ($orig, $self) = (shift, shift);
  my $rc = $self->$orig(@_);
  #
  # LDAP grammar is based on OCTETS STRINGS, i.e. assuming
  # that input is ALREADY percent-decoded. So we explicitely
  # use the _generic implementation to get the unescaped thingy.
  #
  # We also take care to the following fact:
  # - Implementations SHOULD accept as input strings that are not valid UTF-8 strings
  # by doing a second path on every thing not decoded correctly, pushing bytes when
  # this is not a valid UTF-8 string
  #
  my $generic_impl = sprintf('%s::%s::%s', $self->__top, $setup->impl_dirname, '_generic');
  eval "use $generic_impl; 1" || croak $@;
  $rc->{''} = sub {
    my $generic_ri = $generic_impl->new($_[2]);
    #
    # Look to every %XX not yet converted and convert it using ASCII.
    # We do not support invalid 
    #
    my $unescaped = $generic_ri->unescaped;
    $unescaped =~ s/%[A-Fa-f0-9]{2}/chr(hex(${^MATCH}))/egp;
    my $reescaped = $_[0]->percent_encode($unescaped, $RFC3986_characters_no_to_encode);
    #
    # Finally explicity remove the utf8 flag: valid UTF-8 thingies will be replaced by
    # the actions below
    #
    _utf8_off($reescaped);
    $_[0]->_logger->debugf('UTF8-off re-escaped input: %s', $reescaped);
    $reescaped
  };
  $rc->{'UTF8 octets'} = sub { MarpaX::RFC::RFC3629->new($_[2])->output };
  $rc->{'UTFMB'}       = sub { MarpaX::RFC::RFC3629->new($_[2])->output };
  $rc
};

#
# Direct accessors to internal fields, defaulting to the unescaped version
#
sub attributes { @{shift->attrdesc}   }
sub filter     {   shift->filtercomp  }

sub _ldap_recompose {
  my $scheme     = $_[1]->{scheme};
  my $host       = $_[1]->{host};
  my $port       = $_[1]->{port};
  my $dn         = $_[1]->{dn};
  my $scope      = $_[1]->{scope};
  my $filter     = $_[1]->{filter};
  my $attributes = $_[1]->{attributes};
  my $extensions = $_[1]->{extensions};

  my $extensions_maybe = (defined $extensions) ? "?${extensions}" : '';
  my $filter_maybe     = (length($extensions_maybe) || (defined $filter)) ? ('?(' . ($filter // '') . ")$extensions_maybe") : '';
  my $scope_maybe      = (length($filter_maybe) || (defined $scope)) ? ('?' . ($scope // '') . $filter_maybe) : '';
  my $question_maybe   = (length($scope_maybe) || (defined $attributes)) ? ('?' . ($attributes // '') . $scope_maybe) : '';
  my $dn_maybe         = (length($question_maybe) || (defined $dn)) ? ('/' . ($dn // '') . $question_maybe) : '';
  my $host_maybe       = $host // '';
  $host_maybe .= ":${port}" if (length($host) && defined($port));

  my $ldap = '';
  $ldap .= "${scheme}://" if (defined $scheme);
  $ldap .= $host_maybe . $dn_maybe;

  print STDERR blessed($_[0]) . "->new(\"$ldap\")";
  $_[0] = blessed($_[0])->new($ldap)
}

#
# In uri_compat mode, values are passed in the unescaped form. The hook on '' takes care of that.
#
around dn => sub {
  # my ($orig, $self) = (shift, shift);

  my $old = $_[1]->raw('dn');
  if ($#_ >= 2) {
    my $dn = $_[1]->percent_encode($_[2], $RFC3986_characters_no_to_encode, qr/[\?]/);
    # print STDERR "$_[2] => $dn\n";
    $_[1]->_ldap_recompose({
                            dn => $_[2],
                            map { $_ => $_[1]->$_ } qw/scheme host port scope filter extensions/
                           });
  }
  $old;
};

1;
