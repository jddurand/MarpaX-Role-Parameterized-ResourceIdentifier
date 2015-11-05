use strict;
use warnings FATAL => 'all';

package MarpaX::Role::Parameterized::ResourceIdentifier::Role::_generic;

# ABSTRACT: Resource Identifier: Generic syntax semantics role

# VERSION

# AUTHORITY

use Encode qw/encode/;
use MarpaX::RFC::RFC3629;
use Moo::Role;
use MooX::Role::Logger;
use Types::Standard -all;
use Try::Tiny;
#
# Arguments of every callback:
# my ($self, $field, $value, $lhs) = @_;
#
# --------------------------------------------
# http://tools.ietf.org/html/rfc3987
# --------------------------------------------
#
# 3.1.  Mapping of IRIs to URIs
#
# ./.. Systems accepting IRIs MAY convert the ireg-name component of an IRI
#      as follows (before step 2 above) for schemes known to use domain
#      names in ireg-name, if the scheme definition does not allow
#      percent-encoding for ireg-name:
#
#      Replace the ireg-name part of the IRI by the part converted using the
#      ToASCII operation specified in section 4.1 of [RFC3490] on each
#      dot-separated label, and by using U+002E (FULL STOP) as a label
#      separator, with the flag UseSTD3ASCIIRules set to TRUE, and with the
#      flag AllowUnassigned set to FALSE for creating IRIs and set to TRUE
#      otherwise.

around build_uri_converter => sub {
  my ($orig, $self) = (shift, shift);

  my $rc = $self->$orig(@_);
  if ($self->reg_name_is_domain_name) {
    $rc->{reg_name} = sub {
      local $MarpaX::Role::Parameterized::ResourceIdentifier::Role::_generic::AllowUnassigned = 1,
      goto &_domain_to_ascii
    }
  }
  $rc
};

around build_iri_converter => sub {
  my ($orig, $self) = (shift, shift);

  my $rc = $self->$orig(@_);
  if ($self->reg_name_is_domain_name) {
    $rc->{reg_name} = sub {
      local $MarpaX::Role::Parameterized::ResourceIdentifier::Role::_generic::AllowUnassigned = 0,
      goto &_domain_to_ascii
    }
  }
  $rc
};

around build_case_normalizer => sub {
  my ($orig, $self) = (shift, shift);
  my $rc = $self->$orig(@_);
  # --------------------------------------------
  # http://tools.ietf.org/html/rfc3987
  # --------------------------------------------
  #
  # 5.3.2.1.  Case Normalization
  #
  # For all IRIs, the hexadecimal digits within a percent-encoding
  # triplet (e.g., "%3a" versus "%3A") are case-insensitive and therefore
  # should be normalized to use uppercase letters for the digits A - F.
  #
  $rc->{$self->pct_encoded} = sub { uc $_[2] } if (! Undef->check($self->pct_encoded));

  # When an IRI uses components of the generic syntax, the component
  # syntax equivalence rules always apply; namely, that the scheme and
  # US-ASCII only host are case insensitive and therefore should be
  # normalized to lowercase.
  #
  $rc->{scheme} = sub { lc $_[2] };
  $rc->{host}   = sub { $_[2] =~ tr/\0-\x7f//c ? $_[2] : lc($_[2]) };
  $rc
};

around build_percent_encoding_normalizer => sub {
  my ($orig, $self) = (shift, shift);
  my $rc = $self->$orig(@_);
  #
  # --------------------------------------------
  # http://tools.ietf.org/html/rfc3987
  # --------------------------------------------
  #
  # 5.3.2.3.  Percent-Encoding Normalization
  #
  # ./.. IRIs should be normalized by decoding any
  # percent-encoded octet sequence that corresponds to an unreserved
  # character, as described in section 2.3 of [RFC3986].
  #
  $rc->{$self->pct_encoded} = sub { $_[0]->unescape($_[2], $self->unreserved) } if (! Undef->check($self->pct_encoded));
  $rc
};

around build_path_segment_normalizer => sub {
  my ($orig, $self) = (shift, shift);
  my $rc = $self->$orig(@_);
  #
  # --------------------------------------------
  # http://tools.ietf.org/html/rfc3987
  # --------------------------------------------
  #
  # 5.3.2.4.  Path Segment Normalization
  #
  # IRI normalizers should remove dot-segments by
  # applying the remove_dot_segments algorithm to the path, as described
  # in section 5.2.4 of [RFC3986].
  #
  $rc->{path} = sub { $_[0]->remove_dot_segments($_[2]) };
  $rc
};

around build_scheme_based_normalizer => sub {
  my ($orig, $self) = (shift, shift);
  my $rc = $self->$orig(@_);
  # --------------------------------------------
  # http://tools.ietf.org/html/rfc3987
  # --------------------------------------------
  #
  # 5.3.3.  Scheme-Based Normalization
  #
  # In general, an IRI that uses the generic syntax for authority with an
  # empty path should be normalized to a path of "/".
  #
  $rc->{path} = sub { length($_[2]) ? $_[2] : '/' };
  #
  # Likewise, an
  # explicit ":port", for which the port is empty or the default for the
  # scheme, is equivalent to one where the port and its ":" delimiter are
  # elided and thus should be removed by scheme-based normalization
  #
  if (! Undef->check($self->default_port)) {
    my $default_port= quotemeta($self->default_port);
    $rc->{authority} = sub { $_[2] =~ /:$default_port?\z/ ? substr($_[2], 0, $-[0]) : $_[2] }
  }
  $rc
};

sub _domain_to_ascii {
  #
  # Arguments: ($self, $field, $value, $lhs) = @_
  #
  my $self = $_[0];
  my $rc = $_[2];
  try {
    $rc = domain_to_ascii($rc, UseSTD3ASCIIRules => 1, AllowUnassigned => $MarpaX::Role::Parameterized::ResourceIdentifier::Role::_generic::AllowUnassigned)
  } catch {
    $self->_logger->warnf('%s', $_);
    return
  };
  $rc
}

1;
