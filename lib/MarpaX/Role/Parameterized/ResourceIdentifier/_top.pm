use strict;
use warnings FATAL => 'all';

package MarpaX::Role::Parameterized::ResourceIdentifier::_top;

# ABSTRACT: Internationalized Resource Identifier (IRI) : _top role

# VERSION

# AUTHORITY

use MarpaX::Role::Parameterized::ResourceIdentifier::Setup;
use MarpaX::Role::Parameterized::ResourceIdentifier::Types -all;
use Carp qw/croak/;
use Log::Any qw/$log/;
use Module::Runtime qw/use_module/;
use Try::Tiny;
use Type::Params qw/compile/;
use Types::Standard -all;
use Types::TypeTiny qw/StringLike/;
use constant  { TRUE => !!1 };
#
# This is a not true role, though this package allow to inject what we want
#
use MooX::Role::Parameterized::With 'MarpaX::Role::Parameterized::ResourceIdentifier::BUILDARGS'
  => {
      whoami          => __PACKAGE__,
      type            => 'Top',
      second_argument => 'scheme',
     };

our $check_new_abs = compile(
                             StringLike|HashRef|ConsumerOf['MarpaX::Role::Parameterized::ResourceIdentifier'],
                             StringLike|HashRef|ConsumerOf['MarpaX::Role::Parameterized::ResourceIdentifier']
                            );
our $check_is_ri = compile(ConsumerOf['MarpaX::Role::Parameterized::ResourceIdentifier']);

our $setup          = MarpaX::Role::Parameterized::ResourceIdentifier::Setup->instance;
my $_CALLER         = undef;

sub import { $_CALLER = caller }

sub _new_from_specific {
  my ($class, $specific, $args) = @_;

  my $subclass = sprintf('%s::%s', $class, $specific);

  my $self;
  try {
    my %args = %{$args};    # Always do a copy
    use_module($subclass);
    $self = $subclass->new(\%args);
    $self->_set_has_recognized_scheme(TRUE);
  } catch {
    foreach (split(/\n/, "$_")) {
      $log->tracef('%s: %s', $subclass, $_);
    }
    return;
  };
  $self
}

sub _new_from_generic {
  my ($class, $args) = @_;

  my $subclass = sprintf('%s::%s', $class, '_generic');

  my $self;
  try {
    my %args = %{$args};    # Always do a copy
    use_module($subclass);
    $self = $subclass->new(\%args);
  } catch {
    if ($setup->uri_compat) {
      foreach (split(/\n/, "$_")) {
        $log->tracef('%s: %s', $subclass, $_);
      }
    } else {
      croak $_;
    }
    return;
  };
  $self
}

sub _new_from_common {
  my ($class, $args) = @_;

  my $subclass = sprintf('%s::%s', $class, '_common');
  use_module($subclass);
  #
  # Should never fail
  #
  my %args = %{$args};    # Always do a copy
  $subclass->new(\%args)
}

sub new {
  my ($class) = shift;
  #
  # Input always exist, c.f. BUILDARGS
  #
  my $args = $class->BUILDARGS(@_);
  my $input = $args->{input};
  my $scheme = exists($args->{scheme}) ? $args->{scheme} : undef;
  #
  # Specific: may fail, or even not exist
  #
  my $self;
  if ($input =~ /^[A-Za-z][A-Za-z0-9+.-]*(?=:)/p) {
    $self = $class->_new_from_specific(${^MATCH}, $args);
  }
  #
  # else _generic: may fail but try/catch'ed
  #
  $self = $class->_new_from_generic($args) if (! $self);
  #
  # fallback _common : must succeed
  #
  $self = $class->_new_from_common($args) if (! $self);
  #
  # scheme argument
  #
  if (! Undef->check($scheme)) {
    #
    # Used only when input is relative
    #
    if ($self->is_relative) {
      #
      # Per def $scheme is passing SchemeLike|AbsoluteReference|StringifiedAbsoluteReference
      #
      my $real_scheme;
      if (SchemeLike->check($scheme)) {
        $real_scheme = $scheme;
      } elsif (AbsoluteReference->check($scheme)) {
        $real_scheme = $scheme->scheme;
      } elsif (StringifiedAbsoluteReference->check($scheme)) {
        $real_scheme = $_CALLER->new($scheme)->scheme;
      } else {
        croak 'Impossible case';
      }
      $self = $class->_new_from_specific($real_scheme, $args) // $self;
    }
  }

  $self
};

sub new_abs {
  my ($class, $ref, $base, %args) = @_;

  $check_new_abs->($ref, $base);
  my $normalize = $args{normalize} // 0;
  my $strict    = $args{strict} // 1;

  #
  # Make objects out of parameters if there are not yet consumers of MarpaX::Role::Parameterized::ResourceIdentifier
  #
  $ref  = $class->new($ref)  unless eval { $check_is_ri->($ref) };
  $base = $class->new($base) unless eval { $check_is_ri->($base) };
  #
  # 5.2.1.  Pre-parse the Base URI
  #
  # ./.. Note that only the scheme component is required to be
  # present in a base URI; the other components may be empty or
  # undefined.
  #
  croak 'base uri must have at least a scheme' unless Str->check($base->_scheme) && length($base->_scheme);
  #
  # ./.. Normalization of the base URI, as described in Sections 6.2.2 and 6.2.3, is optional
  #
  my $base_indice = $normalize ? $base->indice_normalized : $base->indice_default;
  my %base = (
              scheme    => $base->_scheme($base_indice),
              authority => $base->can('_authority') ? $base->_authority($base_indice) : undef,
              path      => $base->can('_path')      ? $base->_path     ($base_indice) : '',
              query     => $base->can('_query')     ? $base->_query    ($base_indice) : undef,
              fragment  => $base->can('_fragment')  ? $base->_fragment ($base_indice) : undef,
              segments  => $base->can('_segments')  ? $base->_segments ($base_indice) : $setup->uri_compat ? [''] : []
             );

  # 5.2.2.  Transform References
  #
  # -- The URI reference is parsed into the five URI components
  # --
  #
  my %ref = (
             scheme    => $ref->_scheme,
             authority => $ref->can('_authority') ? $ref->_authority : undef,
             path      => $ref->can('_path')      ? $ref->_path      : '',
             query     => $ref->can('_query')     ? $ref->_query     : undef,
             fragment  => $ref->can('_fragment')  ? $ref->_fragment  : undef
            );
  #
  # -- A non-strict parser may ignore a scheme in the reference
  # -- if it is identical to the base URI's scheme.
  #
  if ((! $strict) && ($ref{scheme} eq $base{scheme})) {
    $ref{scheme} = undef;
  }
  my $RI = 'MarpaX::Role::Parameterized::ResourceIdentifier';
  my %target = ();
  if (defined($ref{scheme})) {
    $target{scheme}    = $ref{scheme};
    $target{authority} = $ref{authority};
    $target{path}      = $RI->remove_dot_segments($ref{path});
    $target{query}     = $ref{query};
  } else {
    if (defined($ref{authority})) {
      $target{authority} = $ref{authority};
      $target{path}      = $RI->remove_dot_segments($ref{path});
      $target{query}     = $ref{query};
    } else {
      if (! length($ref{path})) {
        $target{path} = $base{path};
        if (defined($ref{query})) {
          $target{query} = $ref{query};
        } else {
          $target{query} = $base{query};
        }
      } else {
        if (substr($ref{path}, 0, 1) eq '/') {
          $target{path} = $RI->remove_dot_segments($ref{path});
        } else {
          $target{path} = __PACKAGE__->merge(\%base, \%ref);
          $target{path} = $RI->remove_dot_segments($target{path});
        }
        $target{query} = $ref{query};
      }
      $target{authority} = $base{authority};
    }
    $target{scheme} = $base{scheme};
  }
  $target{fragment} = $ref{fragment};
  #
  # Recompose
  #
  my $target = '';
  if (defined($target{scheme})) {
    $target .= $target{scheme};
    $target .= ':'
  }
  if (defined($target{authority})) {
    $target .= '//';
    $target .= $target{authority};
  }
  $target .= $target{path};
  if (defined($target{query})) {
    $target .= '?';
    $target .= $target{query};
  }
  if (defined($target{fragment})) {
    $target .= '#';
    $target .= $target{fragment};
  }

  $class->new($target)
}

#
# 5.2.3.  Merge Paths
#
#
sub merge {
  my ($class, $base_hashref, $ref_hashref) = @_;
  #
  # If the base URI has a defined authority component and an empty
  # path, then return a string consisting of "/" concatenated with the
  # reference's path; otherwise,
  #
  if (defined($base_hashref->{authority}) && ! length($base_hashref->{path})) {
    return '/' . $ref_hashref->{path}
  }
  #
  # return a string consisting of the reference's path component
  # appended to all but the last segment of the base URI's path (i.e.,
  # excluding any characters after the right-most "/" in the base URI
  # path, or excluding the entire base URI path if it does not contain
  # any "/" characters).
  #
  my @segments = @{$base_hashref->{segments}};
  shift(@segments) if ($setup->uri_compat);      # The first empty ''
  pop(@segments);
  push(@segments, $ref_hashref->{path}) if (length($ref_hashref->{path}));
  unshift(@segments, '') if (@segments);         # To have the first '/'
  join('/', @segments)
}

1;
