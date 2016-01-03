use strict;
use warnings FATAL => 'all';

package MarpaX::Role::Parameterized::ResourceIdentifier::Role::ldap;
use MarpaX::Role::Parameterized::ResourceIdentifier::Setup;
use MarpaX::RFC::RFC3629;
use Carp qw/croak/;
use Encode qw/_utf8_off/;
use Scalar::Util qw/blessed/;
use SUPER;

our $setup = MarpaX::Role::Parameterized::ResourceIdentifier::Setup->new;
#
# Note: we exclude sharp '#' character
# Original is:
# our $RFC3986_gen_delims_characters    = qr'(?:[:/?#\[\]@])';
our $RFC3986_gen_delims_characters    = qr'(?:[:/?\[\]@])';
our $RFC3986_sub_delims_characters    = qr'(?:[!$&\'()*+,;=])';
our $RFC3986_reserved_characters      = qr/(?:$RFC3986_gen_delims_characters|$RFC3986_sub_delims_characters)/;
our $RFC3986_unreserved_characters    = qr/(?:[A-Za-z0-9-._~])/;
our $RFC3986_characters_not_to_encode = qr/(?:$RFC3986_reserved_characters|$RFC3986_unreserved_characters)/;

# ABSTRACT: Resource Identifier: ldap syntax semantics common overrides role

# VERSION

# AUTHORITY

use Moo::Role;

around default_port => sub { 389 };

# The following characters are to be escaped when they appear
# in the value to be encoded: ESC, one of <escaped>, leading
# SHARP or SPACE, trailing SPACE, and NULL.
our $ESC            = qr/(?:[\x{5C}])/;                                   # 1 character
our $HEX            = qr/(?:[\x{30}-\x{39}\x{41}-\x{46}\x{61}-\x{66}])/;
our $escaped        = qr/(?:$ESC$HEX$HEX)/;                               # 5 characters
our $leading_sharp  = qr/(?:^[\x{23}])/;                                  # 1 character
our $leading_space  = qr/(?:^[\x{20}])/;                                  # 1 character
our $trailing_space = qr/(?:[\x{20}]$)/;                                  # 1 character
our $NULL           = qr/(?:[\x{00}]$)/;                                  # 1 character
our $ldap_escape    = qr/(?:$escaped|$ESC|$leading_sharp|$leading_space|$trailing_space|$NULL)/;
sub _ldap_escape {
  my ($value) = @_;
  $value =~ s/$ldap_escape/"\\${^MATCH}"/eg;
  $value
}

#
# Arguments of every callback:
# my ($self, $field, $value, $lhs) = @_;
#
around percent_decode => sub {
  my ($orig, $self) = (shift, shift);
  #
  # Implementations SHOULD accept as input strings that are not valid UTF-8 strings
  # We interpret that as asking for ASCII fallback for any invalid UTF-8 string
  #
  $self->$orig(@_, 1);
};

around build_percent_encoding_normalizer => sub {
  my ($orig, $self) = (shift, shift);
  my $rc = $self->$orig(@_);
  #
  # LDAP grammar original grammar is based on OCTETS STRINGS, i.e. assuming
  # that input is ALREADY percent-decoded. So we use the unescaped generic
  # parse result as input to LDAP BNF... available in the "parent" -;
  #
  $rc->{''} = sub {
    my ($self, $field, $value, $lhs) = @_;
    my $unescaped = $MarpaX::Role::Parameterized::ResourceIdentifier::BNF::parent_self->unescaped;
    print STDERR "==> UNESCAPED $unescaped\n";
    $unescaped
  };
  $rc->{'UTF8 octets'} = sub { MarpaX::RFC::RFC3629->new($_[2])->output };
  $rc->{'UTFMB'}       = sub { MarpaX::RFC::RFC3629->new($_[2])->output };
  $rc
};

#
# This will return a reblessed $_[0]
#
sub _ldap_recompose {
  my $scheme           = $_[1]->{scheme};
  my $host_maybe       = $_[1]->{host_maybe};
  my $dn_maybe         = $_[1]->{dn_maybe};

  my $ldap = '';
  $ldap .= "${scheme}://" if defined $scheme;
  $ldap .= $host_maybe // '';
  if (defined $dn_maybe) {
    # print STDERR "==> DN BEFORE LDAP_ESCAPED $dn_maybe\n";
    # $dn_maybe = _ldap_escape($dn_maybe);
    # print STDERR "==> DN AFTER LDAP_ESCAPED $dn_maybe\n";
  }
  $ldap .= $dn_maybe   // '';

  #
  # We are silently generating an LDAP URI, and the spec says:
  #   A generated LDAP URL MUST consist only of the restricted set of
  #   characters included in one of the following three productions defined
  #   in [RFC3986]:
  #
  #   <reserved>
  #   <unreserved>
  #   <pct-encoded>
  #
  print STDERR "==> BEFORE RFC3986 characters: $ldap\n";
  my $rf3986_characters = $_[0]->percent_encode($ldap, $RFC3986_characters_not_to_encode);
  print STDERR "==> RFC3986 characters: $rf3986_characters\n";
  $_[0] = blessed($_[0])->new($rf3986_characters)
}

#
# The followings are equivalent to URI::_ldap
#
around dn => sub {
  # my ($orig, $self) = (shift, shift)
  my $old = $setup->uri_compat ? $_[1]->unescaped('dn') :$_[1]->raw('dn');
  if ($#_ >= 2) {
    my $dn_maybe = '/' . $_[2] . ($_[1]->_question_maybe // '');
    $_[1]->_ldap_recompose({
                            scheme     => $_[1]->_scheme,
                            host_maybe => $_[1]->_host_maybe,
                            dn_maybe   => $dn_maybe
                           })
  }
  $old
};

around host => sub {
  # my ($orig, $self) = (shift, shift)
  my $old = $setup->uri_compat ? $_[1]->unescaped('host_maybe') :$_[1]->raw('host_maybe');
  if ($#_ >= 2) {
    my $host_maybe = $_[2];
    $_[1]->_ldap_recompose({
                            scheme     => $_[1]->_scheme,
                            host_maybe => $host_maybe,
                            dn_maybe   => $_[1]->_dn_maybe
                           })
  }
  $old
};
#
# attributes, internally, is an array of selectors
#
sub attributes {
  my $old = $setup->uri_compat ? $_[0]->unescaped('selector') : $_[0]->raw('selector');
  if ($#_ >= 1) {
    my $attributes = join(',', @_[1..$#_]);
    my $question_maybe = '?' . $attributes . ($_[0]->_scope_maybe // '');
    my $dn_maybe       = '/' . ($_[0]->_dn // '') . $question_maybe;
    $_[0]->_ldap_recompose({
                            scheme     => $_[0]->_scheme,
                            host_maybe => $_[0]->_host_maybe,
                            dn_maybe   => $dn_maybe
                           });
  }
  return join(',', @{$old}) unless wantarray;
  @{$old}
};

around _scope => sub {
  # my ($orig, $self) = @_;
  my $old = $setup->uri_compat ? $_[1]->unescaped('scope') :$_[1]->raw('scope');
  if ($#_ >= 2) {
    my $scope = $_[2];
    my $scope_maybe    = '?' . $scope . ($_[1]->_filter_maybe // '');
    my $question_maybe = '?' . join(',', $_[1]->attributes) . $scope_maybe;
    my $dn_maybe       = '/' . ($_[1]->_dn // '') . $question_maybe;
    $_[1]->_ldap_recompose({
                            scheme     => $_[1]->_scheme,
                            host_maybe => $_[1]->_host_maybe,
                            dn_maybe   => $dn_maybe
                           });
  }
  return undef unless $setup->uri_compat && defined wantarray && defined $old;
  $old
};

around extensions => sub {
  # my ($orig, $self) = @_;
  my $old = $setup->uri_compat ? $_[1]->unescaped('extensions') :$_[1]->raw('extensions');
  my @old = map { /^(.+)=?(.*)/; $1 => ($2 // '') } @{$old};
  if ($#_ >= 2) {
    my %ext = @_[2..$#_];
    my $extensions_maybe = '?' . join(',', map {$_ . '=' . $ext{$_}} keys %ext);
    my $filter_maybe     = '?' . ($_[1]->_filter // '') . $extensions_maybe;
    my $scope_maybe      = '?' . ($_[1]->_scope // '') . $filter_maybe;
    my $question_maybe = '?' . join(',', $_[1]->attributes) . $scope_maybe;
    my $dn_maybe       = '/' . ($_[1]->_dn // '') . $question_maybe;
    $_[1]->_ldap_recompose({
                            scheme     => $_[1]->_scheme,
                            host_maybe => $_[1]->_host_maybe,
                            dn_maybe   => $dn_maybe
                           });
  }
  return undef unless $setup->uri_compat && defined wantarray && defined $old;
  @old
};

around scope => sub {
  # my ($orig, $self) = @_;
  my $old = ($#_ >= 2) ? $_[1]->_scope(@_[2..$#_]) : $_[1]->_scope;
  $old = 'base' unless defined($old) && length($old) && $setup->uri_compat;
  $old
};

around _filter => sub {
  # my ($orig, $self) = @_;
  my $old = $setup->uri_compat ? $_[1]->unescaped('filtercomp') :$_[1]->raw('filtercomp');
  if ($#_ >= 2) {
    my $filter_maybe   = '?' . $_[2] . ($_[1]->_extensions_maybe // '');
    my $scope_maybe    = '?' . ($_[1]->_scope_maybe // '') . $filter_maybe;
    my $question_maybe = '?' . join(',', $_[1]->attributes) . $scope_maybe;
    my $dn_maybe       = '/' . ($_[1]->_dn // '') . $question_maybe;
    $_[1]->_ldap_recompose({
                            scheme     => $_[1]->_scheme,
                            host_maybe => $_[1]->_host_maybe,
                            dn_maybe   => $dn_maybe
                           });
  }
  return undef unless $setup->uri_compat && defined wantarray && defined $old;
  $old
};

around filter => sub {
  # my ($orig, $self) = @_;
  my $old = ($#_ >= 2) ? $_[1]->_filter(@_[2..$#_]) : $_[1]->_filter;
  $old = '(objectClass=*)' unless defined($old) && length($old);
  $old;
};

1;
