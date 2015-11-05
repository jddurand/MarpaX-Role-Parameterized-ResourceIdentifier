use strict;
use warnings FATAL => 'all';

package MarpaX::Role::Parameterized::ResourceIdentifier::BNF;
use Carp qw/croak/;
use Class::Method::Modifiers qw/install_modifier/;
use Data::Dumper;
use Encode qw/encode/;
use Marpa::R2;
use MarpaX::RFC::RFC3629;
use MarpaX::Role::Parameterized::ResourceIdentifier::MarpaTrace;
use MarpaX::Role::Parameterized::ResourceIdentifier::Setup;
use MarpaX::Role::Parameterized::ResourceIdentifier::Types qw/Common Generic/;
use Moo::Role;
use MooX::Role::Logger;
use MooX::HandlesVia;
use MooX::Role::Parameterized;
use Role::Tiny;
use Type::Params qw/compile/;
use Types::Encodings qw/Bytes/;
use Types::Standard -all;
use Try::Tiny;
use constant {
  RAW                         =>  0, # Concat: yes, Normalize: no,  Convert: no
  URI_CONVERTED               =>  1, # Concat: yes, Normalize: no,  Convert: yes
  IRI_CONVERTED               =>  2, # Concat: yes, Normalize: no,  Convert: yes
  CASE_NORMALIZED             =>  3, # Concat: yes, Normalize: yes, Convert: no
  CHARACTER_NORMALIZED        =>  4, # Concat: yes, Normalize: yes, Convert: no
  PERCENT_ENCODING_NORMALIZED =>  5, # Concat: yes, Normalize: yes, Convert: no
  PATH_SEGMENT_NORMALIZED     =>  6, # Concat: yes, Normalize: yes, Convert: no
  SCHEME_BASED_NORMALIZED     =>  7, # Concat: yes, Normalize: yes, Convert: no
  PROTOCOL_BASED_NORMALIZED   =>  8, # Concat: yes, Normalize: yes, Convert: no
  _COUNT                      =>  9
};
our $MAX                         = _COUNT - 1;
our $indice_concatenate_start    = RAW;
our $indice_concatenate_end      = PROTOCOL_BASED_NORMALIZED;
our $indice_normalizer_start     = CASE_NORMALIZED;
our $indice_normalizer_end       = PROTOCOL_BASED_NORMALIZED;
our $indice_converter_start      = URI_CONVERTED;
our $indice_converter_end        = IRI_CONVERTED;
our @normalizer_names = qw/case_normalizer
                           character_normalizer
                           percent_encoding_normalizer
                           path_segment_normalizer
                           scheme_based_normalizer
                           protocol_based_normalizer/;
our @converter_names = qw/uri_converter
                          iri_converter/;
# ------------------------------------------------------------
# Explicit slots for all supported attributes in input, scheme
# is explicitely ignored, it is handled only by _top
# ------------------------------------------------------------
has input                   => ( is => 'rwp', isa => Str,         predicate => 1           ); # Must be set, usually by _top
has has_recognized_scheme   => ( is => 'rwp', isa => Bool,        default => sub {   !!0 } ); # Setted eventually by _top
has octets                  => ( is => 'ro',  isa => Bytes|Undef, default => sub { undef } ); # Setted eventually by _top
has encoding                => ( is => 'ro',  isa => Str|Undef,   default => sub { undef } ); # Setted eventually by _top
has decode_strategy         => ( is => 'ro',  isa => Any,         default => sub { undef } ); # Setted eventually by _top
# ----------------------------------------------------------------------------
# Slots that implementations should 'around' on the builders for customization
# ----------------------------------------------------------------------------
has pct_encoded             => ( is => 'ro',  isa => Str|Undef,   lazy => 1, builder => 'build_pct_encoded' );
has reserved                => ( is => 'ro',  isa => RegexpRef,   lazy => 1, builder => 'build_reserved' );
has unreserved              => ( is => 'ro',  isa => RegexpRef,   lazy => 1, builder => 'build_unreserved' );
has is_character_normalized => ( is => 'ro',  isa => Bool,        lazy => 1, builder => 'build_is_character_normalized' );
has default_port            => ( is => 'ro',  isa => Int|Undef,   lazy => 1, builder => 'build_default_port' );
has reg_name_is_domain_name => ( is => 'ro',  isa => Bool,        lazy => 1, builder => 'build_reg_name_is_domain_name' );
__PACKAGE__->_generate_attributes('normalizer', $indice_normalizer_start, $indice_normalizer_end, @normalizer_names);
__PACKAGE__->_generate_attributes('converter', $indice_converter_start, $indice_converter_end, @converter_names);

# --------------
# Internal slots
# --------------
has _structs                => ( is => 'rw',  isa => ArrayRef[Object] );
has _indice_description     => ( is => 'ro',  isa => ArrayRef[Str], default => sub {
                                   [
                                    'Raw value                        ',
                                    'URI converted value              ',
                                    'IRI converted value              ',
                                    'Case normalized value            ',
                                    'Character normalized value       ',
                                    'Percent encoding normalized value',
                                    'Path segment normalized value    ',
                                    'Scheme based normalized value    ',
                                    'Protocol based normalized value  '
                                   ]
                                 }
                               );

# =============================================================================
# We want parsing to happen immeidately AFTER object was build and then at
# every input reconstruction
# =============================================================================
sub BUILD {
  my ($self) = @_;
  $self->_parse;
  around input => sub {
    my ($orig, $self) = (shift, shift);
    $self->$orig(@_);
    $self->_parse
  }
}
# =============================================================================
# Parameter validation
# =============================================================================
our $check = compile(
                     slurpy
                     Dict[
                          whoami      => Str,
                          type        => Enum[qw/common generic/],
                          bnf         => Str,
                          reserved    => RegexpRef,
                          unreserved  => RegexpRef,
                          pct_encoded => Str|Undef,
                          mapping     => HashRef[Str]
                         ]
                    );

# =============================================================================
# Parameterized role
# =============================================================================
role {
  my $params = shift;

  # -----------------------
  # Sanity checks on params
  # -----------------------
  my ($hash_ref)  = HashRef->($params);
  my ($PARAMS)    = $check->(%{$hash_ref});

  my $whoami      = $PARAMS->{whoami};
  my $type        = $PARAMS->{type};
  my $bnf         = $PARAMS->{bnf};
  my $reserved    = $PARAMS->{reserved};
  my $unreserved  = $PARAMS->{unreserved};
  my $pct_encoded = $PARAMS->{pct_encoded};
  my $mapping     = $PARAMS->{mapping};

  #
  # Make sure $whoami package is doing MooX::Role::Logger is not already
  #
  Role::Tiny->apply_roles_to_package($whoami, 'MooX::Role::Logger') unless $whoami->DOES('MooX::Role::Logger');
  my $action_full_name = sprintf('%s::_action', $whoami);
  #
  # Push on-the-fly the action name
  # This will natively croak if the BNF would provide another hint for implementation
  #
  $bnf = ":default ::= action => $action_full_name\n$bnf";

  my $is_common   = $type eq 'common';
  my $is_generic  = $type eq 'generic';
  #
  # A bnf package must provide correspondance between grammar symbols
  # and fields in a structure, in the form "<xxx>" => yyy.
  # The structure depend on the type: Common or Generic
  #
  my %fields = ();
  my @fields = $is_common ? Common->new->FIELDS : Generic->new->FIELDS;
  map { $fields{$_} = 0 } @fields;
  while (my ($key, $value) = each %{$mapping}) {
    croak "[$type] symbol $key must be in the form <...>"
      unless $key =~ /^<.*>$/;
    croak "[$type] mapping of unknown field $value"
      unless exists $fields{$value};
    $fields{$value}++;
  }
  my @not_found = grep { ! $fields{$_} } keys %fields;
  croak "[$type] Unmapped fields: @not_found" unless ! @not_found;

  # -----
  # Setup
  # -----
  my $setup = MarpaX::Role::Parameterized::ResourceIdentifier::Setup->new;
  my $marpa_trace_terminals = $setup->marpa_trace_terminals;
  my $marpa_trace_values    = $setup->marpa_trace_values;
  my $marpa_trace           = $setup->marpa_trace;
  my $uri_compat            = $setup->uri_compat;

  #
  # -------
  # Logging
  # -------
  #
  # In any case, we want Marpa to be "silent", unless explicitely traced
  #
  my $trace;
  open(my $trace_file_handle, ">", \$trace) || croak "[$type] Cannot open trace filehandle, $!";
  local $MarpaX::Role::Parameterized::ResourceIdentifier::MarpaTrace::bnf_package = $whoami;
  tie ${$trace_file_handle}, 'MarpaX::Role::Parameterized::ResourceIdentifier::MarpaTrace';
  # ---------------------------------------------------------------------
  # This stub will be the one doing the real work, called by Marpa action
  # ---------------------------------------------------------------------
  my %MAPPING = %{$mapping};
  my $args2array_sub = sub {
    my ($self, $lhs, $field, @args) = @_;
    my $rc = [ ('') x _COUNT ];
    #
    # Concatenate
    #
    foreach my $irc ($indice_concatenate_start..$indice_concatenate_end) {
      do { $rc->[$irc] .= ref($args[$_]) ? $args[$_]->[$irc] : $args[$_] } for (0..$#args)
    }
    #
    # Normalize
    #
    for my $inormalizer ($indice_normalizer_start..$indice_normalizer_end) {
      do { $rc->[$inormalizer] = $MarpaX::Role::Parameterized::ResourceIdentifier::BNF::normalizer_wrapper->[$_]->($self, $field, $rc->[$inormalizer], $lhs) } for ($indice_normalizer_start..$inormalizer);
    }
    #
    # Convert
    #
    do { $rc->[$_] = $MarpaX::Role::Parameterized::ResourceIdentifier::BNF::converter_wrapper->[$_]->($self, $field, $rc->[$_], $lhs) } for ($indice_converter_start..$indice_converter_end);

    $rc
  };
  #
  # Parse method installed directly in the BNF package
  #
  my $grammar = Marpa::R2::Scanless::G->new({source => \$bnf});
  my %recognizer_option = (
                           trace_terminals   => $marpa_trace_terminals,
                           trace_values      => $marpa_trace_values,,
                           trace_file_handle => $trace_file_handle,
                           ranking_method    => 'high_rule_only',
                           grammar           => $grammar
                          );
  install_modifier($whoami, 'fresh', '_parse',
                   sub {
                     my ($self) = @_;

                     croak "Input not set" unless $self->has_input;
                     my $input = $self->input;

                     my $r = Marpa::R2::Scanless::R->new(\%recognizer_option);
                     #
                     # For performance reason, cache all $self-> accesses
                     #
                     my $reserved   = $self->reserved;
                     my $unreserved = $self->unreserved;
                     local $MarpaX::Role::Parameterized::ResourceIdentifier::BNF::pct_encoded            = $self->pct_encoded // ''; # Can be undef
                     local $MarpaX::Role::Parameterized::ResourceIdentifier::BNF::reserved_or_unreserved = qr/(?:$reserved|$unreserved)/;
                     local $MarpaX::Role::Parameterized::ResourceIdentifier::BNF::_structs               = $self->_structs([map { $is_common ? Common->new : Generic->new } (0..$MAX)]);
                     local $MarpaX::Role::Parameterized::ResourceIdentifier::BNF::normalizer_wrapper     = $self->_normalizer_wrapper;
                     local $MarpaX::Role::Parameterized::ResourceIdentifier::BNF::converter_wrapper      = $self->_converter_wrapper;
                     #
                     # A very special case is the input itself, before the parsing
                     # We want to apply eventual normalizers and converters on it.
                     # To identify this special, $field and $lhs are both the
                     # empty string, i.e. a situation that can never happen during
                     # parsing
                     #
                     $self->_logger->debugf('%s: %s', $whoami, Data::Dumper->new([$input], ['input                            '])->Dump);
                     #
                     # The normalization ladder
                     #
                     do { $input = $MarpaX::Role::Parameterized::ResourceIdentifier::BNF::normalizer_wrapper->[$_]->($self, '', $input, '') } for ($indice_normalizer_start..$indice_normalizer_end);
                     $self->_logger->debugf('%s: %s', $whoami, Data::Dumper->new([$input], ['Normalized input                 '])->Dump);
                     #
                     # The converters. Every entry is independant.
                     #
                     do { $input = $MarpaX::Role::Parameterized::ResourceIdentifier::BNF::converter_wrapper->[$_]->($self, '', $input, '') } for ($indice_converter_start..$indice_converter_end);
                     $self->_logger->debugf('%s: %s', $whoami, Data::Dumper->new([$input], ['Converted input                  '])->Dump);
                     #
                     # Parse (may croak)
                     #
                     $r->read(\$input);
                     croak "[$type] Parse of the input is ambiguous" if $r->ambiguous;
                     #
                     # Check result
                     #
                     my $value_ref = $r->value($self);
                     croak "[$type] No parse tree value" unless Ref->check($value_ref);
                     my $value = ${$value_ref};
                     croak "[$type] Invalid parse tree value" unless ArrayRef->check($value);
                     #
                     # Store result
                     #
                     foreach (0..$MAX) {
                       $self->_structs->[$_]->output($value->[$_]);
                       $self->_logger->debugf('%s: %s', $whoami, Data::Dumper->new([$self->output_by_indice($_)], [$self->_indice_description->[$_]])->Dump)
                     }
                   }
                  );
  #
  # Inject the action
  #
  install_modifier($whoami, 'fresh', '_action',
                   sub {
                     my ($self, @args) = @_;
                     my $slg         = $Marpa::R2::Context::slg;
                     my ($lhs, @rhs) = map { $slg->symbol_display_form($_) } $slg->rule_expand($Marpa::R2::Context::rule);
                     $lhs = "<$lhs>" if (substr($lhs, 0, 1) ne '<');
                     # $self->_logger->tracef('%s: %s ::= %s', $whoami, $lhs, join(' ', @rhs));
                     my $field = $mapping->{$lhs};
                     # $self->_logger->tracef('%s:   %s[IN] %s', $whoami, $field || $lhs || '', \@args);
                     my $array_ref = $self->$args2array_sub($lhs, $field, @args);
                     # $self->_logger->tracef('%s:   %s[OUT] %s', $whoami, $field || $lhs || '', $array_ref);
                     if (defined($field)) {
                       #
                       # Segments is special
                       #
                       if ($field eq 'segments') {
                         push(@{$MarpaX::Role::Parameterized::ResourceIdentifier::BNF::_structs->[$_]->segments}, $array_ref->[$_]) for (0..$MAX);
                       } else {
                         $MarpaX::Role::Parameterized::ResourceIdentifier::BNF::_structs->[$_]->$field($array_ref->[$_]) for (0..$MAX);
                       }
                     }
                     $array_ref
                   }
                  );
  # ----------------------------------------------------
  # The builders that the implementation should 'around'
  # ----------------------------------------------------
  install_modifier($whoami, 'fresh', 'build_pct_encoded'              => sub {           $pct_encoded });
  install_modifier($whoami, 'fresh', 'build_reserved'                 => sub {              $reserved });
  install_modifier($whoami, 'fresh', 'build_unreserved'               => sub {            $unreserved });
  install_modifier($whoami, 'fresh', 'build_is_character_normalized'  => sub {                    !!1 });
  install_modifier($whoami, 'fresh', 'build_default_port'             => sub {                  undef });
  install_modifier($whoami, 'fresh', 'build_reg_name_is_domain_name'  => sub {                    !!0 });
  foreach (@normalizer_names, @converter_names) {
    install_modifier($whoami, 'fresh', "build_$_"                     => sub {              return {} });
  }
};
# =============================================================================
# Instance methods
# =============================================================================
sub struct_by_type           { $_[0]->_structs->[$_[0]->indice($_[1])] }
sub output_by_type           { $_[0]->struct_by_type($_[1])->output }
sub struct_by_indice         { $_[0]->_structs->[$_[1]] }
sub output_by_indice         { $_[0]->struct_by_indice($_[1])->output }
# =============================================================================
# Class methods
# =============================================================================
sub indice_raw                         {                            RAW }
sub indice_case_normalized             {                CASE_NORMALIZED }
sub indice_character_normalized        {           CHARACTER_NORMALIZED }
sub indice_percent_encoding_normalized {    PERCENT_ENCODING_NORMALIZED }
sub indice_path_segment_normalized     {        PATH_SEGMENT_NORMALIZED }
sub indice_scheme_based_normalized     {        SCHEME_BASED_NORMALIZED }
sub indice_protocol_based_normalized   {      PROTOCOL_BASED_NORMALIZED }
sub indice_uri_converted               {                  URI_CONVERTED }
sub indice_iri_converted               {                  IRI_CONVERTED }
sub indice_normalized                  {         $indice_normalizer_end }
sub indice_default                     {            indice_normalized() }
sub indice {
  my ($class, $what) = @_;

  croak "Invalid undef argument" if (! defined($what));

  if    ($what eq 'RAW'                        ) { return                         RAW }
  elsif ($what eq 'URI_CONVERTED'              ) { return               URI_CONVERTED }
  elsif ($what eq 'IRI_CONVERTED'              ) { return               IRI_CONVERTED }
  elsif ($what eq 'CASE_NORMALIZED'            ) { return             CASE_NORMALIZED }
  elsif ($what eq 'CHARACTER_NORMALIZED'       ) { return        CHARACTER_NORMALIZED }
  elsif ($what eq 'PERCENT_ENCODING_NORMALIZED') { return PERCENT_ENCODING_NORMALIZED }
  elsif ($what eq 'PATH_SEGMENT_NORMALIZED'    ) { return     PATH_SEGMENT_NORMALIZED }
  elsif ($what eq 'SCHEME_BASED_NORMALIZED'    ) { return     SCHEME_BASED_NORMALIZED }
  elsif ($what eq 'PROTOCOL_BASED_NORMALIZED'  ) { return   PROTOCOL_BASED_NORMALIZED }
  else                                           { croak "Invalid argument $what"     }
}

sub percent_encode {
  my ($class, $string, $regexp) = @_;

  my $encoded = $string;
  $encoded =~ s!$regexp!
    {
     #
     # ${^MATCH} is a read-only variable
     # and Encode::encode is affecting $match -;
     #
     my $match = ${^MATCH};
     join('',
          map {
            '%' . uc(unpack('H2', $_))
          } split(//, Encode::encode('UTF-8', $match, Encode::FB_CROAK))
         )
    }
    !egp;
  $encoded
}

sub remove_dot_segments {
  my ($class, $input) = @_;

  #
  # 1.  The input buffer is initialized with the now-appended path
  # components and the output buffer is initialized to the empty
  # string.
  #
  my $output = '';

  # my $i = 0;
  # my $step = ++$i;
  # my $substep = '';
  # printf STDERR "%-10s %-30s %-30s\n", "STEP", "OUTPUT BUFFER", "INPUT BUFFER";
  # printf STDERR "%-10s %-30s %-30s\n", "$step$substep", $output, $input;
  # $step = ++$i;
  #
  # 2.  While the input buffer is not empty, loop as follows:
  #
  while (length($input)) {
    #
    # A. If the input buffer begins with a prefix of "../" or "./",
    #    then remove that prefix from the input buffer; otherwise,
    #
    if (index($input, '../') == 0) {
      substr($input, 0, 3, '');
      # $substep = 'A';
    }
    elsif (index($input, './') == 0) {
      substr($input, 0, 2, '');
      # $substep = 'A';
    }
    #
    # B. if the input buffer begins with a prefix of "/./" or "/.",
    #    where "." is a complete path segment, then replace that
    #    prefix with "/" in the input buffer; otherwise,
    #
    elsif (index($input, '/./') == 0) {
      substr($input, 0, 3, '/');
      # $substep = 'B';
    }
    elsif ($input =~ /^\/\.(?:[\/]|\z)/) {            # Take care this can confuse the other test on '/../ or '/..'
      substr($input, 0, 2, '/');
      # $substep = 'B';
    }
    #
    # C. if the input buffer begins with a prefix of "/../" or "/..",
    #    where ".." is a complete path segment, then replace that
    #    prefix with "/" in the input buffer and remove the last
    #    segment and its preceding "/" (if any) from the output
    #    buffer; otherwise,
    #
    elsif (index($input, '/../') == 0) {
      substr($input, 0, 4, '/');
      $output =~ s/\/?[^\/]*\z//;
      # $substep = 'C';
    }
    elsif ($input =~ /^\/\.\.(?:[^\/]|\z)/) {
      substr($input, 0, 3, '/');
      $output =~ s/\/?[^\/]*\z//;
      # $substep = 'C';
    }
    #
    # D. if the input buffer consists only of "." or "..", then remove
    #    that from the input buffer; otherwise,
    #
    elsif (($input eq '.') || ($input eq '..')) {
      $input = '';
      # $substep = 'D';
    }
    #
    # E. move the first path segment in the input buffer to the end of
    #    the output buffer, including the initial "/" character (if
    #    any) and any subsequent characters up to, but not including,
    #    the next "/" character or the end of the input buffer.
    #
    #    Note: "or the end of the input buffer" ?
    #
    else {
      $input =~ /^\/?([^\/]*)/;                            # This will always match
      $output .= substr($input, $-[0], $+[0] - $-[0], ''); # Note that perl has no problem saying length is zero
      # $substep = 'E';
    }
    # printf STDERR "%-10s %-30s %-30s\n", "$step$substep", $output, $input;
  }
  #
  # 3. Finally, the output buffer is returned as the result of
  #    remove_dot_segments.
  #
  return $output;
}
sub unescape {
  my ($class, $value, $unreserved) = @_;

  my $unescaped_ok = 1;
  my $unescaped;
  try {
    my $octets = '';
    while ($value =~ m/(?<=%)[^%]+/gp) {
      $octets .= chr(hex(${^MATCH}))
    }
    $unescaped = MarpaX::RFC::RFC3629->new($octets)->output
  } catch {
    $unescaped_ok = 0;
    return
  };
  #
  # Keep only characters in the unreserved set
  #
  if ($unescaped_ok) {
    my $new_value = '';
    my $position_in_original_value = 0;
    my $reescaped_ok = 1;
    foreach (split('', $unescaped)) {
      my $reencoded_length;
      try {
        my $character = $_;
        my $reencoded = join('', map { '%' . uc(unpack('H2', $_)) } split(//, encode('UTF-8', $character, Encode::FB_CROAK)));
        $reencoded_length = length($reencoded);
      } catch {
        $reescaped_ok = 0;
      };
      last if (! $reescaped_ok);
      if ($_ =~ $unreserved) {
        $new_value .= $_;
      } else {
        $new_value = substr($value, $position_in_original_value, $reencoded_length);
      }
      $position_in_original_value += $reencoded_length;
    }
    $value = $new_value if ($reescaped_ok);
  }
  $value
}

# =============================================================================
# Internal class methods
# =============================================================================
sub _generate_attributes {
  my $class = shift;
  my $type = shift;
  my ($indice_start, $indice_end) = (shift, shift);
  foreach (@_) {
    my $builder = "build_$_";
    has $_ => (is => 'ro', isa => HashRef[CodeRef],
               lazy => 1,
               builder => $builder,
               handles_via => 'Hash',
               handles => {
                           "get_$_"    => 'get',
                           "set_$_"    => 'set',
                           "exists_$_" => 'exists',
                           "delete_$_" => 'delete',
                           "kv_$_"     => 'kv',
                           "keys_$_"   => 'keys',
                           "values_$_" => 'values',
                          }
              );
  }
  my $_type_names   = "_${type}_names";
  my $_type_wrapper = "_${type}_wrapper";
  my @_type_names = ();
  push(@_type_names, undef) for (0..$indice_start - 1);
  push(@_type_names, @_);
  push(@_type_names, undef) for ($indice_end + 1..$MAX);
  has $_type_names   => (is => 'ro', isa => ArrayRef[Str|Undef], default => sub { \@_type_names });
  has $_type_wrapper => (is => 'ro', isa => ArrayRef[CodeRef|Undef], lazy => 1,
                         handles_via => 'Array',
                         handles => {
                                     "_get_$type" => 'get'
                                    },
                         builder => sub {
                           $_[0]->_build_impl_sub($indice_start, $indice_end, $_type_names)
                         }
                        );
}
# =============================================================================
# Internal instance methods
# =============================================================================
sub _build_impl_sub {
  my ($self, $istart, $iend, $names) = @_;
  my @array = ();
  foreach (0..$MAX) {
    if (($_ < $istart) || ($_ > $iend)) {
      push(@array, undef);
    } else {
      my $name = $self->$names->[$_];
      my $exists = "exists_$name";
      my $getter = "get_$name";
      push(@array, sub {
             # my ($self, $field, $value, $lhs) = @_;
             my $criteria = $_[1] || $_[3] || '';
             #
             # At run-time, in particular Protocol-based normalizers,
             # the callbacks can be altered
             #
             $_[0]->$exists($criteria) ? goto $_[0]->$getter($criteria) : $_[2]
           }
          )
    }
  }
  \@array
}

1;
