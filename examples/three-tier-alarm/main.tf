variable "incident_alerts_topic_arn" {
  description = "DenDenMushi incident SNS topic ARN."
  type        = string
}

variable "instance_id" {
  description = "EC2 instance monitored by this alarm."
  type        = string
}

variable "host_id" {
  description = "DenDenMushi inventory host ID for the instance."
  type        = string
}

resource "aws_cloudwatch_metric_alarm" "high_cpu" {
  alarm_name          = "three-tier-high-cpu"
  alarm_description   = jsonencode({ hostId = var.host_id, runbookVersion = "v1" })
  namespace           = "AWS/EC2"
  metric_name         = "CPUUtilization"
  statistic           = "Average"
  period              = 300
  evaluation_periods  = 2
  threshold           = 80
  comparison_operator = "GreaterThanThreshold"
  treat_missing_data  = "missing"

  dimensions = {
    InstanceId = var.instance_id
  }

  alarm_actions = [var.incident_alerts_topic_arn]
  ok_actions    = [var.incident_alerts_topic_arn]
}
